"""Durable lifecycle controller: every external effect has an operation intent.

Controllers can be restarted or duplicated. Adapter operations are idempotent
and fenced by immutable execution identity, while outbox leases use unique claim
tokens. An expired lease suspects liveness; it never frees a reservation.
"""
from __future__ import annotations

from contextlib import contextmanager
import threading
import math
from dataclasses import asdict, replace
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit, quote
from datetime import timedelta
from typing import Callable

from sqlalchemy import and_, func, or_, select

from .domain import Error, TERMINAL_STATES, new_id, utcnow
from .executor import ExecutionIdentity, ExecutorRefused, UncertainExecution
from .reconciliation import PublicationObservation, remaining_rounds, retry_delay, utc
from .scheduler import LIVE_ALLOCATION_STATES, Scheduler


class Controller:
    def __init__(self, database, executor, provisioner, *, clock: Callable = utcnow,
                 controller_id: str | None = None, heartbeat_timeout: int = 180, renew_interval: float = 20, participants=None):
        self.database, self.executor, self.provisioner = database, executor, provisioner
        self.clock = clock
        self.participants = participants
        self._local = threading.local()
        self._restoration_requested = False
        self.controller_id = controller_id or new_id()
        self.heartbeat_timeout = heartbeat_timeout
        if not 0 < renew_interval <= 30:
            raise ValueError("Reservation renewal interval must be positive and at most 30 seconds")
        self.renew_interval = renew_interval
        self.scheduler = Scheduler(database, clock=clock, admission_storage=self._admission_storage)

    def _admission_storage(self, job):
        planner = getattr(self.provisioner, "admission_storage", None)
        if planner is not None:
            return planner(job)
        # Every adapter prepays the same terminal-copy, state and log guarantees.
        entries = []
        components = job.spec_json["components"]
        manager_pool = next(c["resources"]["pool_id"] for c in components if c["role"] == "owner")
        number = max(1, job.current_attempt)
        for component in components:
            cid = component["component_id"]
            disk = component["resources"]["disk_bytes"]
            for kind, prefix, cap, pool, covered in (
                ("collection_budget", "hf2l-collection", disk + 4 * 1024 * 1024, component["resources"]["pool_id"], False),
                ("log_budget", "hf2l-log", 1024 * 1024, manager_pool, False),
                ("execution_state", "hf2l-state", disk, component["resources"]["pool_id"], True)):
                entries.append({"kind": kind, "external_id": prefix + "://" + job.id + "/" + str(number) + "/" + cid,
                    "component_id": cid, "pool_id": pool, "max_bytes": cap, "covered_by_allocation": covered,
                    "details": {"attempt_number": number, "covered_by_allocation": covered}})
        return entries

    def now(self):
        return utc(self.clock())

    def run_once(self, *, dispatch_limit: int = 20):
        from .retention import RetentionService
        if not self._restoration_requested:
            self._queue_proxy_restoration()
            self._restoration_requested = True
        # Recover persisted running proxies before inspecting their workers or
        # renewing execution leases. Jobs whose recovery is pending remain
        # excluded from ordinary monitoring until that claimed operation ends.
        restored = 0
        for _ in range(dispatch_limit):
            item = self._claim(topics=("restore_proxies",))
            if item is None:
                break
            restored += int(self._process_claim(item))
        RetentionService(self.database, clock=self.clock).request_expiry()
        admissions = self.scheduler.schedule()
        self._monitor()
        dispatched = 0
        for _ in range(dispatch_limit):
            item = self._claim()
            if item is None:
                break
            dispatched += int(self._process_claim(item))
        return {"admitted": len(admissions), "dispatched": dispatched, "restored": restored}

    def _process_claim(self, item):
        if item.topic in {"cleanup", "purge", "expire_artifacts"}:
            return self._process_cleanup_claim(item)
        try:
            completed = self._handle(item)
        except (UncertainExecution, TimeoutError, ConnectionError):
            self._request_failure(item.job_id, "execution_unknown", transient=True)
            completed = True
        except ExecutorRefused as error:
            if error.code in {"stale_epoch", "stale_claim"}:
                self._finish_claim(item, error.code == "stale_epoch")
                return False
            self._request_failure(item.job_id, error.code, transient=error.code in {
                "capacity", "runtime_unhealthy", "lease_expired", "node_quarantined", "proxy_restart_required"})
            completed = True
        except Error as error:
            self._request_failure(item.job_id, error.code, transient=False)
            completed = True
        except Exception as error:
            self._request_failure(item.job_id, "controller_error", transient=False)
            self._finish_claim(item, False, error=type(error).__name__)
            return False
        self._finish_claim(item, completed)
        return completed

    def _process_cleanup_claim(self, item):
        """Cleanup failures retain their intent and storage protection until proof."""
        try:
            completed = self._handle(item)
        except (ExecutorRefused, Error) as error:
            self._finish_claim(item, False, error=error.code[:128])
            return False
        except (UncertainExecution, TimeoutError, ConnectionError):
            self._finish_claim(item, False, error="execution_unknown")
            return False
        except Exception as error:
            self._finish_claim(item, False, error=type(error).__name__[:128])
            return False
        self._finish_claim(item, completed)
        return completed

    def _claim(self, *, topics=None):
        from .models import Outbox
        now = self.now()
        with self.database.transaction() as session:
            query = (select(Outbox).where(
                or_(Outbox.state == "pending", and_(Outbox.state == "processing", Outbox.lease_until <= now)),
                or_(Outbox.next_attempt_at.is_(None), Outbox.next_attempt_at <= now))
                .order_by(Outbox.created_at, Outbox.id).with_for_update(skip_locked=True).limit(1))
            if topics is not None:
                query = query.where(Outbox.topic.in_(topics))
            item = session.scalar(query)
            if item is None:
                return None
            item.state = "processing"
            item.lease_owner = self.controller_id + ":" + new_id()
            item.lease_until = now + timedelta(minutes=5)
            item.attempts += 1
            session.flush()
            session.expunge(item)
            return item

    def _finish_claim(self, claim, done, error=None):
        from .models import Outbox
        with self.database.transaction() as session:
            item = session.scalar(select(Outbox).where(Outbox.id == claim.id).with_for_update())
            if item is None or item.lease_owner != claim.lease_owner:
                return
            item.state = "done" if done else "pending"
            item.last_error = error
            item.lease_until = None
            item.lease_owner = None
            item.next_attempt_at = None if done else self.now() + timedelta(seconds=5)

    def _snapshot(self, job_id, attempt_id=None):
        from .models import Allocation, Attempt, Job
        with self.database.transaction(immediate=False) as session:
            job = session.get(Job, job_id)
            if job is None:
                return None
            attempt = session.get(Attempt, attempt_id) if attempt_id else session.scalar(
                select(Attempt).where(Attempt.job_id == job.id, Attempt.number == job.current_attempt))
            allocations = list(session.scalars(select(Allocation).where(
                Allocation.job_id == job.id,
                Allocation.attempt_id == attempt.id if attempt else False,
                Allocation.state.in_(LIVE_ALLOCATION_STATES)).order_by(Allocation.pool_id, Allocation.id)))
            session.expunge_all()
            return job, attempt, allocations

    def _claim_current(self, claim):
        from .models import Outbox
        with self.database.transaction(immediate=False) as session:
            item = session.get(Outbox, claim.id)
            return bool(item and item.state == "processing" and item.lease_owner == claim.lease_owner
                        and item.lease_until and self.now() < utc(item.lease_until))

    def _require_claim(self):
        claim = getattr(self._local, "claim", None)
        if claim is not None and not self._claim_current(claim):
            raise ExecutorRefused("Controller dispatch claim is stale", "stale_claim")

    def _handle(self, item):
        self._local.claim = item
        try:
            self._require_claim()
            return self._handle_owned(item)
        finally:
            self._local.claim = None

    def _handle_owned(self, item):
        if item.topic == "dispatch":
            return self._dispatch(item)
        if item.topic == "restore_proxies":
            return self._restore_proxies(item)
        if item.topic in ("fence_stop", "prepare_retry", "reconcile"):
            return self._fence(item)
        if item.topic in ("cleanup", "purge", "expire_artifacts"):
            return self._cleanup(item)
        return True

    def _queue_proxy_restoration(self):
        """Request restart recovery through the same durable outbox as dispatch."""
        from .models import Attempt, Job, Outbox
        if not hasattr(self.provisioner, "restore_job_proxies"):
            return
        with self.database.transaction() as session:
            jobs = list(session.scalars(select(Job).where(Job.state == "RUNNING")
                                       .order_by(Job.id).with_for_update()))
            for job in jobs:
                attempt = session.scalar(select(Attempt).where(Attempt.job_id == job.id,
                                                                Attempt.number == job.current_attempt))
                if attempt is None or attempt.epoch != job.epoch:
                    continue
                key = f"restore-proxies:{job.id}:{job.epoch}"
                existing = session.scalar(select(Outbox).where(Outbox.idempotency_key == key).with_for_update())
                if existing is None:
                    session.add(Outbox(id=new_id(), job_id=job.id, attempt_id=attempt.id,
                        attempt_number=attempt.number, topic="restore_proxies", payload_json={"epoch": job.epoch},
                        idempotency_key=key, state="pending", created_at=self.now()))
                elif existing.state == "done":
                    existing.state = "pending"
                    existing.next_attempt_at = self.now()

    def _proxy_restore_pending(self, job):
        from .models import Outbox
        key = f"restore-proxies:{job.id}:{job.epoch}"
        with self.database.transaction(immediate=False) as session:
            row = session.scalar(select(Outbox).where(Outbox.idempotency_key == key))
            return bool(row and row.state != "done")

    def _restore_proxies(self, item):
        snapshot = self._snapshot(item.job_id, item.attempt_id)
        if snapshot is None:
            return True
        job, attempt, _ = snapshot
        if job.state != "RUNNING" or not attempt or attempt.epoch != job.epoch:
            return True
        confirmed = self._operation(job, attempt, "owner", "restore_proxies",
                                    lambda: self.provisioner.restore_job_proxies(job, attempt))
        return confirmed is not False

    def _operation(self, job, attempt, component_id, action, effect, desired=None):
        from .models import Job, ProvisioningOperation
        self._require_claim()
        key = f"{job.id}:{attempt.id}:{attempt.epoch}:{component_id}:{action}"
        with self.database.transaction() as session:
            locked = session.scalar(select(Job).where(Job.id == job.id).with_for_update())
            if locked is None or locked.epoch != attempt.epoch or locked.current_attempt != attempt.number:
                raise ExecutorRefused("Operation belongs to a stale attempt", "stale_epoch")
            op = session.scalar(select(ProvisioningOperation).where(
                ProvisioningOperation.idempotency_key == key).with_for_update())
            if op is None:
                op = ProvisioningOperation(id=new_id(), job_id=job.id, attempt_id=attempt.id,
                    component_id=component_id, operation=action, idempotency_key=key,
                    desired_json={"epoch": attempt.epoch, **(desired or {})}, state="pending",
                    created_at=self.now(), updated_at=self.now())
                session.add(op)
                session.flush()
            operation_id = op.id
        try:
            self._require_claim()
            observed = effect()
            self._require_claim()
        except Exception as error:
            if isinstance(error, ExecutorRefused) and error.code == "stale_claim":
                raise
            with self.database.transaction() as session:
                op = session.get(ProvisioningOperation, operation_id)
                if op.state != "confirmed":
                    op.state = "refused" if isinstance(error, ExecutorRefused) else "unknown"
                op.last_error = getattr(error, "code", type(error).__name__)
                op.updated_at = self.now()
            raise
        with self.database.transaction() as session:
            locked = session.scalar(select(Job).where(Job.id == job.id).with_for_update())
            op = session.get(ProvisioningOperation, operation_id)
            if locked and locked.epoch == attempt.epoch and locked.current_attempt == attempt.number:
                op.state = "confirmed"
                op.observed_json = self._observation(observed)
                op.last_error = None
                op.updated_at = self.now()
        return observed

    @staticmethod
    def _observation(value):
        if hasattr(value, "__dataclass_fields__"):
            result = asdict(value)
            # Execution specifications may include trusted paths. Operations
            # retain only observation metadata, never tokens or credentials.
            return {key: item for key, item in result.items()
                    if key in {"state", "acknowledged", "termination_confirmed", "publication_status",
                               "current_round", "error_code", "transient", "exit_code", "known", "status"}}
        return {"confirmed": value is True}

    @contextmanager
    def _keepalive(self, claim):
        """Renew only this durable claim's acknowledged gang during slow setup."""
        if not hasattr(self.executor, "renew"):
            yield
            return
        stopped = threading.Event()
        failures = []
        def pulse():
            from .models import Allocation, Attempt, Job, Outbox
            while not stopped.wait(self.renew_interval):
                try:
                    with self.database.transaction() as session:
                        item = session.scalar(select(Outbox).where(Outbox.id == claim.id).with_for_update())
                        job = session.get(Job, claim.job_id)
                        if not item or item.state != "processing" or item.lease_owner != claim.lease_owner:
                            failures.append(ExecutorRefused("Controller dispatch claim is stale", "stale_claim"))
                            return
                        if (not job or job.state not in {"PROVISIONING", "STARTING"}
                                or job.deadline_at is None or self.now() >= utc(job.deadline_at)):
                            return
                        attempt = session.get(Attempt, claim.attempt_id)
                        if not attempt or job.epoch != attempt.epoch or job.current_attempt != attempt.number:
                            return
                        item.lease_until = self.now() + timedelta(minutes=5)
                        identities = [ExecutionIdentity(job.id, attempt.id, allocation.component_id, allocation.epoch)
                            for allocation in session.scalars(select(Allocation).where(
                                Allocation.attempt_id == attempt.id, Allocation.acknowledged.is_(True),
                                Allocation.state.in_(LIVE_ALLOCATION_STATES),
                                Allocation.termination_confirmed.is_(False)))]
                    for identity in identities:
                        if stopped.is_set() or not self._current(identity.job_id, identity.attempt_id,
                                                               identity.epoch, {"PROVISIONING", "STARTING"}):
                            return
                        self.executor.renew(identity)
                except Exception as error:
                    failures.append(error)
                    return
        worker = threading.Thread(target=pulse, name="hf2l-dispatch-keepalive", daemon=True)
        worker.start()
        try:
            yield
        finally:
            stopped.set()
            worker.join(timeout=1)
        if failures:
            if isinstance(failures[0], ExecutorRefused) and failures[0].code == "stale_claim":
                raise failures[0]
            raise UncertainExecution("Reservation renewal failed during provisioning") from failures[0]

    def _dispatch(self, item):
        with self._keepalive(item):
            return self._dispatch_reserved(item)

    def _dispatch_reserved(self, item):
        snapshot = self._snapshot(item.job_id, item.attempt_id)
        if not snapshot:
            return True
        job, attempt, allocations = snapshot
        if (attempt is None or job.state not in {"PROVISIONING", "STARTING"}
                or job.epoch != item.payload_json.get("epoch", attempt.epoch) or attempt.epoch != job.epoch):
            return True
        if job.deadline_at and self.now() >= utc(job.deadline_at):
            self._request_failure(job.id, "deadline_exceeded", transient=False)
            return True
        current_round = self.provisioner.current_round(job)
        remaining = remaining_rounds(job.target_round, current_round)
        bundle = self.provisioner.plan(job, attempt, remaining_rounds=remaining)
        specs = bundle.component_specs
        declared_components = {component["component_id"] for component in job.spec_json["components"]}
        if set(specs) != declared_components or not {a.component_id for a in allocations}.issubset(declared_components):
            raise ExecutorRefused("Provisioner component plan differs from admitted gang", "component_plan_mismatch")
        self._renew_reserved_components(job, attempt)
        for allocation in allocations:
            spec = specs[allocation.component_id]
            expected = ExecutionIdentity(job.id, attempt.id, allocation.component_id, job.epoch)
            if spec.identity != expected or spec.pool_id != allocation.pool_id:
                raise ExecutorRefused("Execution plan is not bound to its reservation", "execution_binding_mismatch")
            if allocation.acknowledged:
                continue
            reservation = self._operation(job, attempt, allocation.component_id, "reserve",
                                           lambda spec=spec: self.executor.reserve(spec),
                                           {"allocation_id": allocation.id})
            if not reservation.acknowledged:
                raise UncertainExecution("Local capacity reservation was not durably acknowledged")
            if not self.ack_assignment(job.id, attempt.id, allocation.component_id, job.epoch):
                return True
        if not self._current(job.id, attempt.id, job.epoch, {"PROVISIONING", "STARTING"}):
            return True
        # All managed components have acknowledged before provisioning can
        # initialize data or before any training component may start.
        self._operation(job, attempt, "owner", "provision",
                        lambda: self.provisioner.ensure(job, attempt, remaining_rounds=remaining))
        current_round = self.provisioner.current_round(job)
        remaining = remaining_rounds(job.target_round, current_round)
        if remaining == 0:
            self._request_completion(job.id, current_round)
            return True
        if not self._build_phase(job, attempt, specs):
            return False
        snapshot = self._snapshot(job.id, attempt.id)
        allocations = snapshot[2]
        self._set_phase(job.id, attempt.id, job.epoch, "STARTING", "starting")
        # Owner initializes its private main inside its own sandbox. Participant
        # workers can wait for that main without exposing raw datasets.
        roles = {c["component_id"]: c["role"] for c in job.spec_json["components"]}
        all_running = True
        for allocation in sorted((a for a in allocations if roles[a.component_id] != "build"),
                                 key=lambda a: (roles[a.component_id] != "owner", a.component_id)):
            if not self._current(job.id, attempt.id, job.epoch, {"STARTING", "PROVISIONING"}):
                return True
            identity = specs[allocation.component_id].identity
            observed = self._operation(job, attempt, allocation.component_id, "start",
                                      lambda identity=identity: self.executor.start(identity))
            if observed.state.upper() in {"UNKNOWN", "QUARANTINED"}:
                raise UncertainExecution("Component start outcome is unknown")
            if observed.termination_confirmed:
                latest_round = self.provisioner.current_round(job)
                if latest_round >= job.target_round:
                    self._request_completion(job.id, latest_round)
                else:
                    self._request_failure(job.id, observed.error_code or "component_stopped_early",
                                          transient=observed.transient)
                return True
            all_running = all_running and observed.state.upper() == "RUNNING"
        if not all_running:
            self._set_phase(job.id, attempt.id, job.epoch, "STARTING", "waiting_components")
            return False
        self._set_phase(job.id, attempt.id, job.epoch, "RUNNING", "waiting_participants")
        return True

    def _renew_reserved_components(self, job, attempt):
        if not hasattr(self.executor, "renew"):
            return
        from .models import Allocation
        self._require_claim()
        with self.database.transaction(immediate=False) as session:
            allocations = list(session.scalars(select(Allocation).where(
                Allocation.attempt_id == attempt.id, Allocation.acknowledged.is_(True),
                Allocation.termination_confirmed.is_(False),
                Allocation.state.in_(LIVE_ALLOCATION_STATES))))
        for allocation in allocations:
            self._require_claim()
            if not self._current(job.id, attempt.id, job.epoch, {"PROVISIONING", "STARTING"}):
                return
            self.executor.renew(ExecutionIdentity(job.id, attempt.id, allocation.component_id, allocation.epoch))

    def _build_phase(self, job, attempt, specs):
        """Builds run with their admitted resources before any FL code starts."""
        from .models import Allocation, Attempt
        roles = {component["component_id"]: component["role"] for component in job.spec_json["components"]}
        build_ids = sorted(component_id for component_id, role in roles.items() if role == "build")
        if not build_ids:
            return True
        if not hasattr(self.provisioner, "prepare_build_outputs"):
            raise ExecutorRefused("Approved build preparation is unavailable", "failed_build")
        with self.database.transaction(immediate=False) as session:
            builds = list(session.scalars(select(Allocation).where(
                Allocation.attempt_id == attempt.id, Allocation.component_id.in_(build_ids))
                .order_by(Allocation.component_id)))
            stored_attempt = session.get(Attempt, attempt.id)
            prepared = bool(stored_attempt.details_json.get("build_prepared"))
            session.expunge_all()
        if {allocation.component_id for allocation in builds} != set(build_ids):
            raise ExecutorRefused("Build gang differs from admitted resources", "component_plan_mismatch")
        if not prepared:
            self._set_phase(job.id, attempt.id, job.epoch, "PROVISIONING", "building")
            outputs = {}
            all_finished = True
            for allocation in builds:
                identity = specs[allocation.component_id].identity
                if not self._current(job.id, attempt.id, job.epoch, {"PROVISIONING", "STARTING"}):
                    return False
                observed = self._operation(job, attempt, allocation.component_id, "inspect_build",
                                           lambda identity=identity: self.executor.inspect(identity))
                self._ingest_logs(allocation)
                if observed.state.upper() == "RESERVED":
                    observed = self._operation(job, attempt, allocation.component_id, "start_build",
                                               lambda identity=identity: self.executor.start(identity))
                if observed.state.upper() in {"UNKNOWN", "QUARANTINED"}:
                    raise UncertainExecution("Build execution outcome is unknown")
                if observed.termination_confirmed:
                    if observed.exit_code is None:
                        raise UncertainExecution("Build exit status is unavailable")
                    if observed.exit_code != 0 or observed.error_code:
                        raise ExecutorRefused("Approved sandbox build failed", "failed_build")
                    stopped = self._operation(job, attempt, allocation.component_id, "stop_build",
                                              lambda identity=identity: self.executor.stop(identity, grace_seconds=60))
                    if not stopped.termination_confirmed:
                        raise UncertainExecution("Build termination could not be confirmed")
                    self.stop_confirmation(job.id, attempt.id, allocation.component_id, job.epoch)
                    self._reserve_collection(job, attempt, allocation)
                    outputs[allocation.component_id] = self._operation(job, attempt, allocation.component_id,
                        "collect_build", lambda identity=identity: self.executor.collect(identity))
                    self._store_collected(job, attempt, allocation, outputs[allocation.component_id])
                    self._ingest_logs(allocation, terminal=True)
                else:
                    all_finished = False
            if not all_finished:
                self._renew_reserved_components(job, attempt)
                return False
            try:
                prepared_outputs = self._operation(job, attempt, "owner", "prepare_build_outputs",
                                lambda: self.provisioner.prepare_build_outputs(job, attempt, outputs),
                                {"build_components": build_ids})
                if prepared_outputs is False or prepared_outputs is None:
                    raise ExecutorRefused("Build preparation was not confirmed", "failed_build")
            except (TimeoutError, ConnectionError, UncertainExecution):
                raise
            except ExecutorRefused:
                raise
            except Exception as error:
                raise ExecutorRefused("Collected build outputs failed validation", "failed_build") from error
            self._require_claim()
            with self.database.transaction() as session:
                stored = session.get(Attempt, attempt.id)
                stored.details_json = {**stored.details_json, "build_prepared": True,
                                       "build_components": build_ids}
        live = [allocation for allocation in builds if allocation.state in LIVE_ALLOCATION_STATES]
        if live and not self._release(job, attempt, live):
            raise UncertainExecution("Stopped build resources could not be released")
        return True

    def _current(self, job_id, attempt_id, epoch, states=None):
        snapshot = self._snapshot(job_id, attempt_id)
        return bool(snapshot and snapshot[1] and snapshot[0].epoch == epoch
                    and snapshot[1].number == snapshot[0].current_attempt
                    and (states is None or snapshot[0].state in states))

    def _set_phase(self, job_id, attempt_id, epoch, state, phase):
        from .models import Allocation, Attempt, Job, Project
        with self.database.transaction() as session:
            project_id = session.scalar(select(Job.project_id).where(Job.id == job_id))
            if project_id is None:
                return False
            session.scalar(select(Project).where(Project.id == project_id).with_for_update())
            job = session.scalar(select(Job).where(Job.id == job_id).with_for_update())
            attempt = session.get(Attempt, attempt_id)
            if not job or not attempt or job.epoch != epoch or job.current_attempt != attempt.number or job.state in TERMINAL_STATES | {"CANCELLING", "RECONCILING", "NEEDS_ATTENTION"}:
                return False
            job.state, job.phase = state, phase
            job.version += 1
            job.updated_at = self.now()
            attempt.state = state
            attempt.heartbeat_at = self.now()
            if state == "RUNNING" and attempt.started_at is None:
                attempt.started_at = self.now()
            for allocation in session.scalars(select(Allocation).where(
                    Allocation.attempt_id == attempt_id, Allocation.state.in_(LIVE_ALLOCATION_STATES))):
                if state != "PROVISIONING":
                    allocation.state = state
            Scheduler._event(session, job, state.lower(), {}, self.now())
            return True

    def _request_failure(self, job_id, code, *, transient):
        from .models import Allocation, Attempt, Job
        if job_id is None:
            return
        with self.database.transaction() as session:
            job = session.scalar(select(Job).where(Job.id == job_id).with_for_update())
            if not job or job.state in TERMINAL_STATES | {"CANCELLING", "NEEDS_ATTENTION"}:
                return
            attempt = session.scalar(select(Attempt).where(Attempt.job_id == job_id,
                                                          Attempt.number == job.current_attempt))
            if attempt and code == "deadline_exceeded" and "desired_terminal" not in attempt.details_json:
                attempt.details_json = {**attempt.details_json, "desired_terminal": "FAILED",
                                        "desired_terminal_reason": "deadline_exceeded"}
            if job.state == "RECONCILING":
                return
            job.state, job.phase = "RECONCILING", "fencing"
            job.error_code = code
            job.version += 1
            job.updated_at = self.now()
            if attempt:
                attempt.error_code = code
                attempt.details_json = {**attempt.details_json, "transient": transient}
            for allocation in session.scalars(select(Allocation).where(
                    Allocation.job_id == job_id, Allocation.state.in_(LIVE_ALLOCATION_STATES))):
                allocation.state = "QUARANTINED"
            Scheduler._outbox(session, job, "fence_stop", {"reason": code, "transient": transient},
                              attempt.id if attempt else None)
            Scheduler._event(session, job, "reconciling", {"reason": code}, self.now())

    def _request_completion(self, job_id, current_round):
        from .models import Attempt, Job
        with self.database.transaction() as session:
            job = session.scalar(select(Job).where(Job.id == job_id).with_for_update())
            if not job or job.state in TERMINAL_STATES | {"CANCELLING", "NEEDS_ATTENTION", "RECONCILING"}:
                return
            attempt = session.scalar(select(Attempt).where(Attempt.job_id == job_id,
                                                          Attempt.number == job.current_attempt))
            job.current_round = max(job.current_round, current_round)
            job.state, job.phase = "RECONCILING", "collecting_results"
            job.version += 1
            job.updated_at = self.now()
            Scheduler._outbox(session, job, "fence_stop", {"success": True}, attempt.id if attempt else None)

    def _other_dispatch_active(self, job_id):
        from .models import Outbox
        with self.database.transaction(immediate=False) as session:
            return session.scalar(select(Outbox.id).where(Outbox.job_id == job_id,
                Outbox.topic == "dispatch", Outbox.state == "processing",
                Outbox.lease_until > self.now()).limit(1)) is not None

    def _confirm_never_started(self, job_id, attempt_id):
        """Prove a queued attempt had no permitted external effect.

        Every reservation, dispatch and provisioning effect has a durable intent.
        An empty current-attempt ledger, checked under the job lock, therefore
        proves absence. Older retained data needs confirmed predecessor fencing;
        missing acknowledgements or elapsed leases never prove absence.
        This also repairs terminal queued cancellations recorded before this
        proof was persisted, without changing evidence for executed attempts.
        """
        from .models import Allocation, Attempt, Job, Outbox, ProvisioningOperation, ProvisioningResource
        self._require_claim()
        with self.database.transaction() as session:
            job = session.scalar(select(Job).where(Job.id == job_id).with_for_update())
            attempt = session.scalar(select(Attempt).where(Attempt.id == attempt_id).with_for_update())
            if (job is None or attempt is None or attempt.job_id != job.id
                    or attempt.number != job.current_attempt or attempt.epoch not in {job.epoch, job.epoch + 1}
                    or job.state not in {"CANCELLING", "CANCELLED", "FAILED"}
                    or attempt.state not in {"QUEUED", "CANCELLED", "FAILED"}
                    or attempt.started_at is not None or attempt.heartbeat_at is not None
                    or attempt.node_id is not None or attempt.resources_json
                    or attempt.publication_status not in {"none", "absent"}
                    or set(attempt.details_json or {}) - {
                        "desired_terminal", "desired_terminal_reason", "automatic_retries", "never_started_cleanup"}):
                return False
            for model in (Allocation, ProvisioningOperation, ProvisioningResource):
                if session.scalar(select(model.id).where(model.job_id == job.id,
                        model.attempt_id == attempt.id).limit(1)) is not None:
                    return False
            # A queued retry may retain an older execution's results. Its
            # stopped/revoked predecessor evidence must be positive, and all
            # remaining resources must be retained data rather than credentials
            # or an unfinished external effect.
            previous = list(session.scalars(select(Attempt).where(
                Attempt.job_id == job.id, Attempt.id != attempt.id)))
            previous_ids = {row.id for row in previous}
            if any(not row.revocation_confirmed or not row.termination_confirmed
                    or row.publication_status not in {"none", "absent", "confirmed", "published"}
                    for row in previous):
                return False
            historical_allocations = list(session.scalars(select(Allocation).where(Allocation.job_id == job.id)))
            if any(row.attempt_id not in previous_ids or row.state != "RELEASED"
                    or row.released_at is None or not row.termination_confirmed for row in historical_allocations):
                return False
            historical_operations = list(session.scalars(select(ProvisioningOperation).where(
                ProvisioningOperation.job_id == job.id)))
            previous_by_id = {row.id: row for row in previous}
            components = {item["component_id"] for item in job.spec_json["components"]}
            from .resources import stable_key
            safe_refusals = {"capacity", "invalid_resources", "job_deadline_expired",
                             "unsupported_profile", "node_mismatch", "pool_mismatch", "invalid_identity"}
            def operation_closed(row):
                if row.attempt_id not in previous_ids or row.component_id not in components:
                    return False
                old = previous_by_id[row.attempt_id]
                identity = f"{job.id}:{old.id}:{old.epoch}:{row.component_id}:"
                if row.state == "ready" and row.last_error is None:
                    # The trusted provisioner has distinct shared/attempt keys.
                    return (row.idempotency_key in {
                        stable_key("hf2l", job.id, old.id, row.component_id, row.operation),
                        stable_key("hf2l", job.id, "", row.component_id, row.operation)}
                        and row.desired_json.get("epoch", old.epoch) == old.epoch)
                if row.state == "confirmed" and row.last_error is None:
                    return (row.idempotency_key == identity + row.operation
                            and row.desired_json.get("epoch") == old.epoch)
                if (row.operation != "reserve" or row.idempotency_key != identity + "reserve"
                        or row.desired_json.get("epoch") != old.epoch):
                    return False
                if row.state == "refused" and row.last_error in safe_refusals:
                    return True
                if row.state != "unknown":
                    return False
                # A lost node reservation reply is settled by exact positive
                # stop/collection/release evidence, never by lease expiration.
                allocation = next((value for value in historical_allocations
                    if value.attempt_id == old.id and value.component_id == row.component_id
                    and value.epoch == old.epoch), None)
                if allocation is None:
                    return False
                closed = {}
                for effect in historical_operations:
                    if (effect.attempt_id == old.id and effect.component_id == row.component_id
                            and effect.operation in {"stop", "collect", "release"}
                            and effect.idempotency_key == identity + effect.operation
                            and effect.desired_json.get("epoch") == old.epoch
                            and effect.state == "confirmed" and effect.last_error is None):
                        closed[effect.operation] = effect
                return (set(closed) == {"stop", "collect", "release"}
                    and closed["stop"].observed_json.get("termination_confirmed") is True
                    and closed["release"].observed_json.get("confirmed") is True)
            if any(not operation_closed(row) for row in historical_operations):
                return False
            historical_resources = list(session.scalars(select(ProvisioningResource).where(
                ProvisioningResource.job_id == job.id)))
            data_kinds = {"source", "build_products", "component_state", "execution_state",
                          "retained_output", "retained_artifact_root", "collection_budget", "log_budget"}
            for row in historical_resources:
                old = previous_by_id.get(row.attempt_id)
                ownership = row.ownership_json or {}
                if (old is None or row.component_id not in components
                        or ownership.get("job_id") != job.id
                        or ownership.get("component_id") != row.component_id
                        or ownership.get("attempt_id", old.id) != old.id
                        or ownership.get("epoch", old.epoch) != old.epoch
                        or ownership.get("kind", row.kind) != row.kind):
                    return False
                if row.deleted_at is not None or row.state == "deleted":
                    continue
                if not row.retained or row.kind not in data_kinds:
                    return False
                if row.state == "planned" and row.kind in {"collection_budget", "log_budget"}:
                    pointer = "collection_resource_id" if row.kind == "collection_budget" else "log_resource_id"
                    if not any(value.attempt_id == old.id and value.component_id == row.component_id
                            and value.epoch == old.epoch and value.details_json.get(pointer) == row.id
                            for value in historical_allocations):
                        return False
                elif row.state not in {"ready", "retained"}:
                    return False
            retries = (attempt.details_json or {}).get("automatic_retries", 0)
            if type(retries) is not int or not 0 <= retries <= 3:
                return False
            if session.scalar(select(Outbox.id).where(Outbox.job_id == job.id,
                    Outbox.topic.in_(("dispatch", "restore_proxies")),
                    Outbox.state != "done").limit(1)) is not None:
                return False
            if attempt.revocation_confirmed and attempt.termination_confirmed:
                return True
            attempt.revocation_confirmed = True
            attempt.termination_confirmed = True
            attempt.publication_status = "absent"
            attempt.details_json = {**(attempt.details_json or {}), "never_started_cleanup": {
                "reason": "never_dispatched", "authority": "manager_operation_ledger",
                "no_current_attempt_effects": True, "fenced_prior_attempts": sorted(previous_ids)}}
            job.version += 1
            job.updated_at = self.now()
            Scheduler._event(session, job, "attempt.never_started_cleanup_confirmed",
                             {"attempt_id": attempt.id, "reason": "never_dispatched"}, self.now())
            return True

    def _fence(self, item):
        from .models import Allocation, Attempt, Job, Project
        snapshot = self._snapshot(item.job_id, item.attempt_id)
        if snapshot is None:
            return True
        job, attempt, allocations = snapshot
        if item.attempt_number is not None and item.attempt_number != job.current_attempt:
            return True
        if job.state in TERMINAL_STATES:
            return True
        if attempt is None:
            self._terminal(job.id, "CANCELLED", "cancelled")
            return True
        if not allocations and attempt.state == "QUEUED" and job.state == "CANCELLING":
            if not self._confirm_never_started(job.id, attempt.id):
                self._attention(job.id, "queued_cancellation_effects_unconfirmed")
                return True
            reason = "deadline_exceeded" if job.phase == "deadline_exceeded" else "cancelled"
            self._terminal(job.id, "FAILED" if reason == "deadline_exceeded" else "CANCELLED", reason)
            return True
        if attempt.number != job.current_attempt or attempt.epoch != job.epoch:
            return True
        if job.state == "CANCELLING" or (job.deadline_at and self.now() >= utc(job.deadline_at)):
            desired_reason = "deadline_exceeded" if job.phase == "deadline_exceeded" or item.payload_json.get("reason") == "deadline_exceeded" or job.state != "CANCELLING" else "cancelled"
            with self.database.transaction() as session:
                stored = session.get(Attempt, attempt.id)
                if "desired_terminal" not in stored.details_json:
                    stored.details_json = {**stored.details_json,
                        "desired_terminal": "FAILED" if desired_reason == "deadline_exceeded" else "CANCELLED",
                        "desired_terminal_reason": desired_reason}
        revoked = self._operation(job, attempt, "owner", "revoke",
                                  lambda: self.provisioner.revoke(job, attempt))
        if revoked is not True:
            self._attention(job.id, "grant_revocation_unknown")
            return True
        with self.database.transaction() as session:
            stored = session.get(Attempt, attempt.id)
            stored.revocation_confirmed = True
        # Cancellation cannot free a reservation while an in-flight dispatch
        # still has permission to complete a node start operation.
        if self._other_dispatch_active(job.id):
            return False
        all_stopped = True
        for allocation in allocations:
            identity = ExecutionIdentity(job.id, attempt.id, allocation.component_id, allocation.epoch)
            if self._never_reserved(job, attempt, allocation.component_id):
                self.stop_confirmation(job.id, attempt.id, allocation.component_id, job.epoch)
                continue
            try:
                observed = self._operation(job, attempt, allocation.component_id, "stop",
                                          lambda identity=identity: self.executor.stop(identity, grace_seconds=60))
                confirmed = observed.termination_confirmed
            except (ExecutorRefused, UncertainExecution):
                confirmed = False
            if confirmed:
                self.stop_confirmation(job.id, attempt.id, allocation.component_id, job.epoch)
            all_stopped = all_stopped and confirmed
        if self.participants is not None:
            self.participants.request_stop(job, attempt)
            all_stopped = all_stopped and self.participants.attempt_termination_confirmed(job.id, attempt.id)
        else:
            from .models import ProvisioningResource
            with self.database.transaction(immediate=False) as session:
                external = list(session.scalars(select(ProvisioningResource).where(
                    ProvisioningResource.job_id == job.id, ProvisioningResource.kind == "external_enrollment")))
                all_stopped = all_stopped and all(resource.details_json.get("termination_confirmed", False)
                                                for resource in external)
        if not all_stopped:
            self._quarantine(job.id)
            return False
        if item.topic == "reconcile" and item.payload_json.get("evidence"):
            attempt.details_json = {**attempt.details_json, "reconciliation_evidence": item.payload_json["evidence"]}
            with self.database.transaction() as session:
                stored = session.get(Attempt, attempt.id)
                stored.details_json = attempt.details_json
        publication = self._operation(job, attempt, "owner", "reconcile",
                                      lambda: self.provisioner.reconcile(job, attempt))
        if not isinstance(publication, PublicationObservation) or not publication.known:
            self._attention(job.id, "publication_unknown")
            return True
        with self.database.transaction() as session:
            stored = session.get(Attempt, attempt.id)
            stored.publication_status = publication.status
            stored.termination_confirmed = True
            stored.ended_at = self.now()
            stored.state = "STOPPED"
            stored.details_json = {**stored.details_json, "publication_evidence": publication.evidence or {}}
            locked = session.scalar(select(Job).where(Job.id == job.id).with_for_update())
            if publication.current_round is not None:
                locked.current_round = max(locked.current_round, publication.current_round)
        if not self._release(job, attempt, allocations):
            self._quarantine(job.id)
            return False
        # Re-read desired state after the external fencing barrier. Cancellation
        # wins if it committed while a final-success observation was in flight.
        job, attempt, _ = self._snapshot(job.id)
        if job.state == "CANCELLING":
            reason = "deadline_exceeded" if job.phase == "deadline_exceeded" or item.payload_json.get("reason") == "deadline_exceeded" else "cancelled"
            self._terminal(job.id, "FAILED" if reason == "deadline_exceeded" else "CANCELLED", reason)
        elif attempt.details_json.get("desired_terminal") in {"CANCELLED", "FAILED"}:
            self._terminal(job.id, attempt.details_json["desired_terminal"], attempt.details_json["desired_terminal_reason"])
        elif item.payload_json.get("reason") == "deadline_exceeded" or job.error_code == "deadline_exceeded":
            self._terminal(job.id, "FAILED", "deadline_exceeded")
        elif publication.current_round is not None and publication.current_round >= job.target_round:
            self._terminal(job.id, "SUCCEEDED", "target_round_confirmed")
        elif item.topic == "reconcile" and not item.payload_json.get("retry"):
            self._terminal(job.id, "FAILED", job.error_code or "reconciled_failure")
        elif item.topic == "prepare_retry":
            return self._retry(job.id, manual=True)
        elif attempt.details_json.get("transient") or item.payload_json.get("transient"):
            return self._retry(job.id, manual=False)
        else:
            self._terminal(job.id, "FAILED", job.error_code or "execution_failed")
        return True

    def _never_reserved(self, job, attempt, component_id):
        from .models import ProvisioningOperation
        key = f"{job.id}:{attempt.id}:{attempt.epoch}:{component_id}:reserve"
        with self.database.transaction(immediate=False) as session:
            operation = session.scalar(select(ProvisioningOperation).where(ProvisioningOperation.idempotency_key == key))
            return operation is None or (operation.state == "refused" and operation.last_error in {
                "capacity", "invalid_resources", "job_deadline_expired", "unsupported_profile",
                "node_mismatch", "pool_mismatch", "invalid_identity"})

    def _release(self, job, attempt, allocations):
        from .models import Allocation, GpuAllocation, Job, Pool, Project
        for allocation in allocations:
            identity = ExecutionIdentity(job.id, attempt.id, allocation.component_id, allocation.epoch)
            if not self._never_reserved(job, attempt, allocation.component_id):
                try:
                    self._reserve_collection(job, attempt, allocation)
                    collected = self._operation(job, attempt, allocation.component_id, "collect",
                                    lambda identity=identity: self.executor.collect(identity))
                    self._store_collected(job, attempt, allocation, collected)
                    self._ingest_logs(allocation, terminal=True)
                    self._retain_execution_state(job, attempt, allocation)
                    released = self._operation(job, attempt, allocation.component_id, "release",
                                               lambda identity=identity: self.executor.release(identity))
                except Error as error:
                    self._attention(job.id, error.code)
                    return False
                except (ExecutorRefused, UncertainExecution):
                    return False
                if released is not True:
                    return False
            with self.database.transaction() as session:
                session.scalar(select(Pool).where(Pool.id == allocation.pool_id).with_for_update())
                project = session.scalar(select(Project).where(Project.id == job.project_id).with_for_update())
                session.scalar(select(Job).where(Job.id == job.id).with_for_update())
                stored = session.scalar(select(Allocation).where(Allocation.id == allocation.id).with_for_update())
                if not stored.termination_confirmed:
                    return False
                stored.state = "RELEASED"
                stored.released_at = self.now()
                for gpu in session.scalars(select(GpuAllocation).where(
                        GpuAllocation.allocation_id == stored.id, GpuAllocation.released_at.is_(None))):
                    gpu.released_at = self.now()
        return True

    def _reserve_collection(self, job, attempt, allocation):
        """Prepay every possible opaque copy before node collection writes bytes."""
        from .models import Allocation, Job, Pool, Project, ProvisioningResource
        from .resources import stable_key
        from .retention import RetentionService
        cap = allocation.disk_bytes + 4 * 1024 * 1024
        with self.database.transaction() as session:
            pool = session.scalar(select(Pool).where(Pool.id == allocation.pool_id).with_for_update())
            project = session.scalar(select(Project).where(Project.id == job.project_id).with_for_update())
            stored_job = session.scalar(select(Job).where(Job.id == job.id).with_for_update())
            stored = session.scalar(select(Allocation).where(Allocation.id == allocation.id).with_for_update())
            if (not stored_job or not stored or stored_job.epoch != attempt.epoch
                    or stored_job.current_attempt != attempt.number or stored.epoch != attempt.epoch):
                raise ExecutorRefused("Collection reservation belongs to a stale attempt", "stale_epoch")
            collection_id = (stored.details_json or {}).get("collection_resource_id")
            resource = (session.scalar(select(ProvisioningResource).where(ProvisioningResource.id == collection_id)
                        .with_for_update()) if collection_id else
                session.scalar(select(ProvisioningResource).where(
                    ProvisioningResource.kind == "collection_budget", ProvisioningResource.external_id == allocation.id)
                    .with_for_update()))
            if resource is not None and (resource.job_id != job.id or resource.kind != "collection_budget"
                    or resource.component_id != allocation.component_id
                    or resource.details_json.get("pool_id") != allocation.pool_id):
                raise ExecutorRefused("Collection budget differs from its allocation", "unsafe_output")
            if resource is None:
                resource = ProvisioningResource(
                    id=stable_key("collection-budget", allocation.id)[:32], job_id=job.id, attempt_id=attempt.id,
                    component_id=allocation.component_id, kind="collection_budget", external_id=allocation.id,
                    ownership_json={"job_id": job.id, "attempt_id": attempt.id,
                                    "component_id": allocation.component_id, "epoch": allocation.epoch},
                    details_json={"pool_id": allocation.pool_id,
                                  "node_id": (allocation.details_json or {}).get("node_id")},
                    state="planned", retained=True, created_at=self.now(), updated_at=self.now())
                session.add(resource)
                session.flush()
            RetentionService.reserve_in_transaction(session, resource, project, cap, pool)
            return resource.id

    def _retain_execution_state(self, job, attempt, allocation):
        from .models import Allocation, Job, Pool, Project, ProvisioningResource
        from .retention import RetentionService
        with self.database.transaction() as session:
            session.scalar(select(Pool).where(Pool.id == allocation.pool_id).with_for_update())
            project = session.scalar(select(Project).where(Project.id == job.project_id).with_for_update())
            session.scalar(select(Job).where(Job.id == job.id).with_for_update())
            stored = session.scalar(select(Allocation).where(Allocation.id == allocation.id).with_for_update())
            state_id = (stored.details_json or {}).get("retained_resource_id")
            resource = (session.scalar(select(ProvisioningResource).where(ProvisioningResource.id == state_id)
                        .with_for_update()) if state_id else
                session.scalar(select(ProvisioningResource).where(
                    ProvisioningResource.kind == "execution_state", ProvisioningResource.external_id == allocation.id)
                    .with_for_update()))
            if resource is not None and (resource.job_id != job.id or resource.attempt_id != attempt.id
                    or resource.kind != "execution_state" or resource.component_id != allocation.component_id
                    or resource.details_json.get("pool_id", allocation.pool_id) != allocation.pool_id):
                raise ExecutorRefused("Retained state budget differs from its allocation", "unsafe_output")
            if resource is None:
                resource = ProvisioningResource(id=new_id(), job_id=job.id, attempt_id=attempt.id,
                    component_id=allocation.component_id, kind="execution_state", external_id=allocation.id,
                    ownership_json={"job_id": job.id, "attempt_id": attempt.id,
                                    "component_id": allocation.component_id, "epoch": allocation.epoch},
                    state="retained", retained=True, created_at=self.now(), updated_at=self.now())
                session.add(resource)
                session.flush()
            RetentionService.charge_in_transaction(session, resource, project, allocation.disk_bytes)
            resource.state = "retained"
            stored.details_json = {**stored.details_json, "retained_disk_charged": True,
                                   "retained_resource_id": resource.id, "storage_deleted": False}

    def _store_collected(self, job, attempt, allocation, collected):
        from .models import Artifact, Job, Pool, Project, ProvisioningResource
        from .retention import RetentionService
        if not isinstance(collected, (tuple, list)) or len(collected) > 1000:
            raise ExecutorRefused("Collector result exceeds its bounded manifest", "unsafe_output")
        with self.database.transaction() as session:
            session.scalar(select(Pool).where(Pool.id == allocation.pool_id).with_for_update())
            project = session.scalar(select(Project).where(Project.id == job.project_id).with_for_update())
            stored_job = session.scalar(select(Job).where(Job.id == job.id).with_for_update())
            collection_id = (allocation.details_json or {}).get("collection_resource_id")
            reservation = (session.scalar(select(ProvisioningResource).where(ProvisioningResource.id == collection_id)
                           .with_for_update()) if collection_id else
                session.scalar(select(ProvisioningResource).where(
                    ProvisioningResource.kind == "collection_budget", ProvisioningResource.external_id == allocation.id)
                    .with_for_update()))
            if reservation is None:
                raise Error(409, "retained_resource_reservation_required")
            children = []
            for item in collected:
                locator = getattr(item, "locator", None)
                if locator is None:
                    continue
                if (not isinstance(locator, str) or len(locator) > 1024
                        or type(item.size_bytes) is not int or item.size_bytes < 0
                        or not isinstance(item.sha256, str) or len(item.sha256) != 64
                        or not isinstance(item.path, str)):
                    raise ExecutorRefused("Collector returned an invalid retained artifact", "unsafe_output")
                relative = PurePosixPath(item.path)
                if relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in item.path.split("/")):
                    raise ExecutorRefused("Collector path is not canonical", "unsafe_output")
                parsed = urlsplit(locator)
                if parsed.scheme == "hf2l-node":
                    identity = ExecutionIdentity(job.id, attempt.id, allocation.component_id, allocation.epoch)
                    pool = session.get(Pool, allocation.pool_id)
                    node_id = (allocation.details_json or {}).get("node_id") or (pool.node_id if pool else None)
                    expected_path = "/" + identity.key + "/" + quote(item.path, safe="/")
                    if (not node_id or parsed.netloc != node_id or parsed.path != expected_path
                            or parsed.query or parsed.fragment or parsed.username or parsed.password):
                        raise ExecutorRefused("Remote artifact locator differs from its registered node", "unsafe_output")
                    root = "hf2l-node://" + node_id + "/" + identity.key
                else:
                    location = Path(locator)
                    if parsed.scheme or not location.is_absolute() or tuple(location.parts[-len(relative.parts):]) != relative.parts:
                        raise ExecutorRefused("Retained locator differs from collected path", "unsafe_output")
                    root = location.parents[len(relative.parts) - 1]
                root_resource = session.scalar(select(ProvisioningResource).where(
                    ProvisioningResource.kind == "retained_artifact_root", ProvisioningResource.external_id == str(root)))
                if root_resource is None:
                    root_resource = ProvisioningResource(id=new_id(), job_id=job.id, attempt_id=attempt.id,
                        component_id=allocation.component_id, kind="retained_artifact_root", external_id=str(root),
                        ownership_json={"job_id": job.id, "attempt_id": attempt.id,
                                        "component_id": allocation.component_id, "epoch": allocation.epoch},
                        details_json={"root": str(root), "pool_id": allocation.pool_id,
                                      "node_id": (allocation.details_json or {}).get("node_id")}, state="retained",
                        retained=True, size_bytes=0, created_at=self.now(), updated_at=self.now())
                    session.add(root_resource)
                    session.flush()
                if root_resource.job_id != job.id or root_resource.component_id != allocation.component_id:
                    raise ExecutorRefused("Retained root ownership differs", "unsafe_output")
                existing = session.scalar(select(Artifact).where(Artifact.job_id == job.id,
                                                                  Artifact.storage_key == locator))
                if existing is not None:
                    if existing.sha256 != item.sha256 or existing.size_bytes != item.size_bytes:
                        raise ExecutorRefused("Retained artifact identity changed", "unsafe_output")
                    resource = session.scalar(select(ProvisioningResource).where(
                        ProvisioningResource.kind == "retained_output", ProvisioningResource.external_id == locator))
                    if resource is None:
                        raise Error(409, "retained_storage_ledger_inconsistent")
                    children.append(resource)
                    continue
                resource = session.scalar(select(ProvisioningResource).where(
                    ProvisioningResource.kind == "retained_output", ProvisioningResource.external_id == locator))
                if resource is None:
                    resource = ProvisioningResource(id=new_id(), job_id=job.id, attempt_id=attempt.id,
                        component_id=allocation.component_id, kind="retained_output", external_id=locator,
                        ownership_json={"job_id": job.id, "attempt_id": attempt.id,
                                        "component_id": allocation.component_id, "epoch": allocation.epoch},
                        state="retained", retained=True, size_bytes=item.size_bytes,
                        details_json={"pool_id": allocation.pool_id,
                            "node_id": (allocation.details_json or {}).get("node_id")},
                        created_at=self.now(), updated_at=self.now())
                    session.add(resource)
                    session.flush()
                if resource.size_bytes != item.size_bytes:
                    raise Error(409, "retained_resource_charge_conflict")
                children.append(resource)
                session.add(Artifact(id=new_id(), job_id=job.id, attempt_number=attempt.number,
                    kind="checkpoint" if item.path.endswith((".bin", ".pt", ".safetensors")) else "output",
                    name=(allocation.component_id + "/" + item.path)[:256], size_bytes=item.size_bytes,
                    sha256=item.sha256, storage_key=locator,
                    locator_json={"kind": "local", "resource_id": root_resource.id, "relative_path": item.path},
                    state="retained", created_at=self.now(),
                    expires_at=stored_job.artifacts_expire_at))
            RetentionService.transfer_reserved_in_transaction(session, reservation, project, children, retain_unused=True)
            session.flush()

    def _retry(self, job_id, *, manual):
        from .models import Artifact, Attempt, Job, LogChunk
        with self.database.transaction() as session:
            job = session.scalar(select(Job).where(Job.id == job_id).with_for_update())
            attempt = session.scalar(select(Attempt).where(Attempt.job_id == job_id, Attempt.number == job.current_attempt))
            if job.state != "RECONCILING" or not attempt.revocation_confirmed or not attempt.termination_confirmed or attempt.publication_status not in {"none", "absent", "confirmed", "published"}:
                return False
            if job.deadline_at and self.now() >= utc(job.deadline_at):
                self._terminal_in_transaction(session, job, "FAILED", "deadline_exceeded")
                return True
            retries = int(attempt.details_json.get("automatic_retries", 0))
            if not manual and retries >= 3:
                self._terminal_in_transaction(session, job, "FAILED", "retry_exhausted")
                return True
            retries = 0 if manual else retries + 1
            job.current_attempt += 1
            job.attempt_count = max(job.attempt_count, job.current_attempt)
            # The scheduler raises epoch when the new attempt is admitted.
            next_epoch = job.epoch + 1
            session.add(Attempt(id=new_id(), job_id=job.id, number=job.current_attempt,
                epoch=next_epoch, state="QUEUED", details_json={"automatic_retries": retries}, created_at=self.now()))
            job.state, job.phase = "QUEUED", "waiting_resources"
            job.terminated_at = None
            job.artifacts_expire_at = None
            job.cleanup_status = "none"
            for artifact in session.scalars(select(Artifact).where(Artifact.job_id == job.id, Artifact.deleted_at.is_(None))):
                artifact.expires_at = None
            for chunk in session.scalars(select(LogChunk).where(LogChunk.job_id == job.id, LogChunk.deleted_at.is_(None))):
                chunk.expires_at = None
            job.next_attempt_at = self.now() if manual else self.now() + timedelta(seconds=retry_delay(retries))
            job.queue_reason = {"code": "dependencies", "available_at": job.next_attempt_at.isoformat()}
            job.error_code = None
            job.version += 1
            job.updated_at = self.now()
            Scheduler._event(session, job, "retry_queued", {"manual": manual, "automatic_retries": retries}, self.now())
            return True

    def _attention(self, job_id, reason):
        from .models import Job
        with self.database.transaction() as session:
            job = session.scalar(select(Job).where(Job.id == job_id).with_for_update())
            if job and job.state not in TERMINAL_STATES:
                job.state, job.phase = "NEEDS_ATTENTION", "reconciliation_required"
                job.error_code = reason
                job.version += 1
                job.updated_at = self.now()
                Scheduler._event(session, job, "needs_attention", {"reason": reason}, self.now())

    def _quarantine(self, job_id):
        from .models import Allocation
        with self.database.transaction() as session:
            for allocation in session.scalars(select(Allocation).where(
                    Allocation.job_id == job_id, Allocation.state.in_(LIVE_ALLOCATION_STATES))):
                allocation.state = "QUARANTINED"

    def _terminal(self, job_id, state, reason):
        from .models import Job
        with self.database.transaction() as session:
            job = session.scalar(select(Job).where(Job.id == job_id).with_for_update())
            if job:
                self._terminal_in_transaction(session, job, state, reason)

    def _terminal_in_transaction(self, session, job, state, reason):
        from .models import Artifact, Attempt, LogChunk, Project
        if job.state in TERMINAL_STATES:
            return False
        if job.state == "CANCELLING" and state == "SUCCEEDED":
            return False
        job.state, job.phase = state, "finished"
        job.outcome_reason = reason
        job.error_code = reason if state == "FAILED" else None
        job.backfill_count = 0
        job.terminated_at = self.now()
        job.updated_at = self.now()
        attempt = session.scalar(select(Attempt).where(Attempt.job_id == job.id, Attempt.number == job.current_attempt))
        if attempt:
            attempt.state = state
            attempt.ended_at = self.now()
        project = session.get(Project, job.project_id)
        job.artifacts_expire_at = self.now() + timedelta(days=project.retention_days)
        for artifact in session.scalars(select(Artifact).where(Artifact.job_id == job.id, Artifact.deleted_at.is_(None))):
            artifact.expires_at = job.artifacts_expire_at
        for chunk in session.scalars(select(LogChunk).where(LogChunk.job_id == job.id, LogChunk.deleted_at.is_(None))):
            chunk.expires_at = job.artifacts_expire_at
        job.cleanup_status = "pending"
        job.version += 1
        Scheduler._event(session, job, state.lower(), {"reason": reason}, self.now())
        Scheduler._outbox(session, job, "cleanup", {})
        return True

    def _cleanup(self, item):
        from .models import Allocation, Job, Pool, Project, ProvisioningResource
        from .retention import RetentionService
        snapshot = self._snapshot(item.job_id)
        if not snapshot:
            return True
        job, attempt, allocations = snapshot
        if job.state not in TERMINAL_STATES or allocations:
            return False
        deletes_storage = item.topic in {"purge", "expire_artifacts"}
        if job.purged_at is not None or (item.topic == "cleanup" and job.cleanup_status in {
                "purge_pending", "expiry_pending", "expired"}):
            return True
        if item.topic == "expire_artifacts" and job.cleanup_status == "purge_pending":
            return True
        if deletes_storage:
            with self.database.transaction(immediate=False) as session:
                retained = list(session.scalars(select(Allocation).where(
                    Allocation.job_id == job.id, Allocation.state == "RELEASED")))
                session.expunge_all()
            for allocation in retained:
                if allocation.details_json.get("storage_deleted") or not allocation.details_json.get("retained_disk_charged"):
                    continue
                identity = ExecutionIdentity(job.id, allocation.attempt_id, allocation.component_id, allocation.epoch)
                self._require_claim()
                if not hasattr(self.executor, "purge") or self.executor.purge(identity) is not True:
                    return False
            self._require_claim()
            confirmed = (self.provisioner.purge_job(job) if item.topic == "purge"
                         else self.provisioner.expire_artifacts(job))
            self._require_claim()
            if confirmed:
                with self.database.transaction() as session:
                    for pool_id in sorted({allocation.pool_id for allocation in retained}):
                        session.scalar(select(Pool).where(Pool.id == pool_id).with_for_update())
                    session.scalar(select(Project).where(Project.id == job.project_id).with_for_update())
                    session.scalar(select(Job).where(Job.id == job.id).with_for_update())
                    for allocation in session.scalars(select(Allocation).where(
                            Allocation.job_id == job.id, Allocation.state == "RELEASED").with_for_update()):
                        allocation.details_json = {**allocation.details_json, "storage_deleted": True}
                    for resource in session.scalars(select(ProvisioningResource).where(
                            ProvisioningResource.job_id == job.id,
                            ProvisioningResource.kind.in_(("execution_state", "retained_output", "retained_artifact_root", "collection_budget"))).with_for_update()):
                        if resource.ownership_json.get("job_id") != job.id:
                            raise ExecutorRefused("Retained resource ownership differs", "unsafe_output")
                        resource.state = "deleted"
                        resource.deleted_at = self.now()
                        resource.updated_at = self.now()
                # The shared retention service releases every owned source,
                # output, checkpoint and DB-log charge exactly once, only after
                # the resource ledger proves that all storage is deleted.
                RetentionService(self.database, clock=self.clock).confirm_job_data_deleted(job.id)
        else:
            self._require_claim()
            if attempt is not None and (not attempt.revocation_confirmed or not attempt.termination_confirmed):
                if self._confirm_never_started(job.id, attempt.id):
                    job, attempt, allocations = self._snapshot(job.id, attempt.id)
            confirmed = self.provisioner.cleanup(job, attempt)
            self._require_claim()
        with self.database.transaction() as session:
            stored = session.scalar(select(Job).where(Job.id == job.id).with_for_update())
            # An older ordinary cleanup may finish after a user requested purge.
            # Its result cannot clear the durable authorization for raw deletion.
            if not deletes_storage and (stored.purged_at is not None or stored.cleanup_status in {
                    "purge_pending", "expiry_pending", "expired"}):
                return True
            if deletes_storage:
                stored.cleanup_status = ("expired" if item.topic == "expire_artifacts" else "complete") if confirmed else (
                    "purge_pending" if item.topic == "purge" else "expiry_pending")
            else:
                stored.cleanup_status = "complete" if confirmed else "failed"
            if confirmed and item.topic == "purge":
                stored.purged_at = self.now()
            stored.version += 1
            stored.updated_at = self.now()
            Scheduler._event(session, stored,
                "purged" if confirmed and item.topic == "purge" else "artifacts_expired" if confirmed and item.topic == "expire_artifacts" else "cleanup",
                {"confirmed": confirmed}, self.now())
        return bool(confirmed)

    def _ingest_logs(self, allocation, *, terminal=False):
        if not hasattr(self.executor, "read_logs"):
            return None
        from .log_stream import ingest_component_logs
        try:
            return ingest_component_logs(self.database, self.executor, allocation,
                clock=self.clock, terminal=terminal, max_chunks=16 if terminal else 1)
        except (Error, ExecutorRefused, UncertainExecution, TimeoutError, ConnectionError, ValueError):
            # Execution lifecycle and durable collection remain independently
            # fenced when optional bounded log transport cannot advance.
            return None

    def _monitor(self):
        from .models import Attempt, Job
        with self.database.transaction(immediate=False) as session:
            ids = list(session.scalars(select(Job.id).where(Job.state.in_(("RUNNING", "STARTING", "PROVISIONING")))))
        for job_id in ids:
            job, attempt, allocations = self._snapshot(job_id)
            if job.deadline_at and self.now() >= utc(job.deadline_at):
                self._request_failure(job.id, "deadline_exceeded", transient=False)
                continue
            if job.state == "RUNNING" and self._proxy_restore_pending(job):
                continue
            if job.state == "PROVISIONING":
                continue
            if attempt.heartbeat_at and self.now() - utc(attempt.heartbeat_at) > timedelta(seconds=self.heartbeat_timeout):
                self._request_failure(job.id, "heartbeat_expired", transient=True)
                continue
            try:
                current_round = self.provisioner.current_round(job)
                self._authoritative_round(job.id, current_round)
                if current_round >= job.target_round:
                    self._request_completion(job.id, current_round)
                    continue
                for allocation in allocations:
                    identity = ExecutionIdentity(job.id, attempt.id, allocation.component_id, allocation.epoch)
                    observed = self.executor.inspect(identity)
                    self._ingest_logs(allocation)
                    if observed.error_code or observed.state.upper() in {"FAILED", "QUARANTINED", "UNKNOWN"}:
                        self._request_failure(job.id, observed.error_code or "execution_unknown", transient=observed.transient)
                        break
                    if observed.termination_confirmed:
                        self._request_failure(job.id, "component_stopped_early", transient=observed.transient)
                        break
                    if hasattr(self.executor, "renew"):
                        self.executor.renew(identity)
                    self.heartbeat(job.id, attempt.id, allocation.component_id, job.epoch)
                    self.progress(job.id, attempt.id, allocation.component_id, job.epoch,
                                  current_round=observed.current_round if observed.current_round is not None else current_round,
                                  publication_status=observed.publication_status,
                                  phase=getattr(observed, "phase", None) or (getattr(observed, "details", None) or {}).get("phase"),
                                  metrics=getattr(observed, "metrics", None),
                                  readiness=getattr(observed, "readiness", None) or (getattr(observed, "details", None) or {}).get("readiness"))
            except (ExecutorRefused, UncertainExecution, TimeoutError, ConnectionError):
                self._request_failure(job.id, "heartbeat_lost", transient=True)
            except ValueError:
                self._request_failure(job.id, "invalid_runtime_progress", transient=False)

    def check_assignment(self, node_id, pool_id, job_id, attempt_id, component_id, epoch):
        from .models import Allocation, Attempt, Job, Pool
        with self.database.transaction(immediate=False) as session:
            job, attempt, pool = session.get(Job, job_id), session.get(Attempt, attempt_id), session.get(Pool, pool_id)
            if (not job or not attempt or not pool or attempt.job_id != job.id
                    or job.epoch != epoch or attempt.epoch != epoch or attempt.number != job.current_attempt):
                return False
            allocation = session.scalar(select(Allocation).where(Allocation.job_id == job_id,
                Allocation.attempt_id == attempt_id, Allocation.component_id == component_id,
                Allocation.pool_id == pool_id, Allocation.epoch == epoch,
                Allocation.state.in_(LIVE_ALLOCATION_STATES)).limit(1))
            if allocation is None:
                return False
            assigned_node = (allocation.details_json or {}).get("node_id") or pool.node_id
            return assigned_node == node_id

    def _callback(self, job_id, attempt_id, component_id, epoch, apply):
        from .models import Allocation, Attempt, Job, Project
        with self.database.transaction() as session:
            project_id = session.scalar(select(Job.project_id).where(Job.id == job_id))
            if project_id is None:
                return False
            session.scalar(select(Project).where(Project.id == project_id).with_for_update())
            job = session.scalar(select(Job).where(Job.id == job_id).with_for_update())
            attempt = session.get(Attempt, attempt_id)
            if not job or not attempt or job.epoch != epoch or attempt.epoch != epoch or job.current_attempt != attempt.number or job.state in TERMINAL_STATES:
                return False
            allocation = session.scalar(select(Allocation).where(Allocation.job_id == job_id,
                Allocation.attempt_id == attempt_id, Allocation.component_id == component_id,
                Allocation.epoch == epoch, Allocation.state.in_(LIVE_ALLOCATION_STATES)).with_for_update())
            if allocation is None:
                return False
            apply(session, job, attempt, allocation)
            return True

    def ack_assignment(self, job_id, attempt_id, component_id, epoch):
        def apply(session, job, attempt, allocation):
            allocation.acknowledged = True
            allocation.state = "ACKNOWLEDGED"
            attempt.heartbeat_at = self.now()
        return self._callback(job_id, attempt_id, component_id, epoch, apply)

    def heartbeat(self, job_id, attempt_id, component_id, epoch):
        def apply(session, job, attempt, allocation):
            attempt.heartbeat_at = self.now()
        return self._callback(job_id, attempt_id, component_id, epoch, apply)

    def progress(self, job_id, attempt_id, component_id, epoch, *, current_round=None,
                 phase=None, publication_status=None, metrics=None, readiness=None):
        if current_round is not None and (type(current_round) is not int or current_round < 0):
            raise ValueError("Round progress must be a non-negative integer")
        if publication_status is not None and publication_status not in {"none", "absent", "confirmed", "published", "unknown", "publishing", "ambiguous", "not_observed"}:
            raise ValueError("Invalid publication status")
        # Finite worker/Exchange observations map to manager lifecycle phases;
        # the original observation remains bounded component telemetry.
        reported_phase = phase
        phase = {"not_ready": "waiting_participants", "ready": "waiting_participants",
                 "idle": "waiting_participants", "waiting_initialization": "initializing",
                 "initialized": "waiting_participants", "submitted": "waiting_participants",
                 "published": "publishing", "completed": "collecting_results",
                 "skipped": "waiting_participants", "retry": "waiting_participants",
                 "retry_authorized": "initializing", "running": "training",
                 "uncertain": "publishing", "needs_attention": "publishing",
                 "stopped": "collecting_results", "failed": "collecting_results",
                 "duration_exceeded": "collecting_results"}.get(phase, phase)
        if phase is not None and phase not in {"fetching", "building", "initializing", "aggregating", "waiting_participants", "training", "publishing", "collecting_results"}:
            raise ValueError("Invalid progress phase")
        if readiness is not None and readiness not in {"initializing", "waiting", "ready", "training", "finished", "failed"}:
            raise ValueError("Invalid component readiness")
        if metrics is not None:
            if not isinstance(metrics, dict) or len(metrics) > 32 or any(
                not isinstance(key, str) or not key or len(key) > 64
                or type(value) not in (int, float) or not math.isfinite(value)
                for key, value in metrics.items()):
                raise ValueError("Metrics must be a bounded finite numeric mapping")
        def apply(session, job, attempt, allocation):
            components = dict(attempt.details_json.get("components", {}))
            report = dict(components.get(component_id, {}))
            before = dict(report)
            for key, value in {"current_round": current_round, "phase": phase,
                               "metrics": metrics, "readiness": readiness}.items():
                if value is not None:
                    report[key] = value
            if publication_status is not None:
                report["publication_status"] = publication_status
            if reported_phase is not None:
                report["reported_phase"] = reported_phase
            changed = before != report
            report["observed_at"] = self.now().isoformat().replace("+00:00", "Z")
            components[component_id] = report
            attempt.details_json = {**attempt.details_json, "components": components}
            if changed:
                role = next((component["role"] for component in job.spec_json["components"]
                             if component["component_id"] == component_id), None)
                if phase is not None and ((role == "owner" and job.state in {"RUNNING", "STARTING", "PROVISIONING"})
                        or (role == "build" and job.state == "PROVISIONING")):
                    job.phase = phase
                job.version += 1
                job.updated_at = self.now()
                Scheduler._event(session, job, "progress", {"component_id": component_id,
                    "current_round": report.get("current_round"), "phase": report.get("phase")}, self.now())
        return self._callback(job_id, attempt_id, component_id, epoch, apply)

    def _authoritative_round(self, job_id, current_round):
        from .models import Job
        with self.database.transaction() as session:
            job = session.scalar(select(Job).where(Job.id == job_id).with_for_update())
            if job and job.state in {"RUNNING", "STARTING"} and current_round > job.current_round:
                job.current_round = current_round
                job.version += 1
                job.updated_at = self.now()
                Scheduler._event(session, job, "round_confirmed", {"current_round": current_round}, self.now())

    def stop_confirmation(self, job_id, attempt_id, component_id, epoch):
        def apply(session, job, attempt, allocation):
            allocation.termination_confirmed = True
            allocation.state = "RELEASING"
        return self._callback(job_id, attempt_id, component_id, epoch, apply)

    def append_logs(self, job_id, attempt_id, component_id, epoch, *, data):
        if not isinstance(data, str) or len(data.encode("utf-8")) > 65536:
            raise ValueError("Log chunk exceeds the bounded input size")
        def apply(session, job, attempt, allocation):
            from .models import LogChunk, Project, ProvisioningResource
            from .retention import RetentionService
            sequence = (session.scalar(select(func.max(LogChunk.sequence)).where(
                LogChunk.job_id == job_id, LogChunk.component == component_id)) or 0) + 1
            chunk = LogChunk(job_id=job_id, attempt_number=attempt.number, component=component_id,
                sequence=sequence, data=data, created_at=self.now(), expires_at=job.artifacts_expire_at)
            session.add(chunk)
            budget_id = (allocation.details_json or {}).get("log_resource_id")
            budget = (session.scalar(select(ProvisioningResource).where(ProvisioningResource.id == budget_id)
                      .with_for_update()) if budget_id else None)
            if budget_id and (budget is None or budget.attempt_id != attempt.id):
                raise Error(409, "retained_resource_ownership_mismatch")
            RetentionService.charge_log_in_transaction(session, session.get(Project, job.project_id), chunk, budget=budget)
        return self._callback(job_id, attempt_id, component_id, epoch, apply)
