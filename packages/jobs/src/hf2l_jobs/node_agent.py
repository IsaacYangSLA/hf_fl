"""Durable local reservations, fenced execution leases, and fail-closed node API."""
from __future__ import annotations
from contextlib import contextmanager
from dataclasses import asdict
import fcntl
import hashlib
import inspect as inspect_module
import json
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time
from typing import Callable
from starlette.requests import Request
from .executor import (ExecutionIdentity, ExecutionSpec, ResourceLimits, Reservation,
                       RuntimeObservation, ExecutorRefused, UncertainExecution)

EXECUTION_STORAGE_HEADROOM_BYTES = 4 * 1024 * 1024

def execution_storage_budget_bytes(disk_bytes: int) -> int:
    """Keep both bounded state copies and output/log metadata charged to purge."""
    if type(disk_bytes) is not int or disk_bytes <= 0:
        raise ExecutorRefused("Invalid execution storage budget", "invalid_resources")
    return 2 * disk_bytes + EXECUTION_STORAGE_HEADROOM_BYTES

class NodeAgent:
    """Local ACK ledger. Expiry stops workloads but never frees capacity."""
    def __init__(self, executor, ledger_path, node_id: str, pool_id: str,
                 capacity: ResourceLimits, *, clock: Callable[[], float] = time.monotonic,
                 wall_clock: Callable[[], float] = time.time, boot_id: str | None = None,
                 watchdog_interval: float = 1.0):
        self.executor = executor
        self.ledger_path = str(ledger_path)
        self.node_id, self.pool_id, self.capacity = node_id, pool_id, capacity
        self.clock, self.wall_clock = clock, wall_clock
        self.boot_id = boot_id or Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.lock = threading.RLock()
        self._operations = {}
        self._components = {}
        self._operations_lock = threading.RLock()
        self._guard_depth = threading.local()
        Path(self.ledger_path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._db = sqlite3.connect(self.ledger_path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS executions(
              execution_key TEXT PRIMARY KEY, job_id TEXT NOT NULL,
              attempt_id TEXT NOT NULL, component_id TEXT NOT NULL,
              epoch INTEGER NOT NULL, spec TEXT NOT NULL, state TEXT NOT NULL,
              cpu_millis INTEGER NOT NULL, memory_bytes INTEGER NOT NULL,
              disk_bytes INTEGER NOT NULL, lease_until REAL NOT NULL,
              deadline REAL, boot_id TEXT NOT NULL, stopped INTEGER NOT NULL DEFAULT 0);
            CREATE UNIQUE INDEX IF NOT EXISTS active_component
              ON executions(job_id,component_id) WHERE state != 'RELEASED';
            CREATE TABLE IF NOT EXISTS fences(
              job_id TEXT NOT NULL, component_id TEXT NOT NULL,
              epoch INTEGER NOT NULL, PRIMARY KEY(job_id,component_id));
            CREATE TABLE IF NOT EXISTS shared_auxiliary(
              job_id TEXT NOT NULL, component_id TEXT NOT NULL,
              reserved_bytes INTEGER NOT NULL, PRIMARY KEY(job_id,component_id));
        """)
        columns = {row["name"] for row in self._db.execute("PRAGMA table_info(executions)")}
        if "disk_released" not in columns:
            self._db.execute("ALTER TABLE executions ADD COLUMN disk_released INTEGER NOT NULL DEFAULT 0")
        if "retained_output_bytes" not in columns:
            self._db.execute("ALTER TABLE executions ADD COLUMN retained_output_bytes INTEGER NOT NULL DEFAULT 0")
        if "auxiliary_bytes" not in columns:
            self._db.execute("ALTER TABLE executions ADD COLUMN auxiliary_bytes INTEGER NOT NULL DEFAULT 0")
        if "executor_absent" not in columns:
            self._db.execute("ALTER TABLE executions ADD COLUMN executor_absent INTEGER NOT NULL DEFAULT 0")
        os.chmod(self.ledger_path, 0o600)
        if not 0.1 <= watchdog_interval <= 60:
            raise ValueError("Invalid local watchdog interval")
        self._watchdog_stop = threading.Event()
        if hasattr(self.executor, "lease_guard"):
            self.executor.lease_guard = self._allow_launch
        def monitor():
            while not self._watchdog_stop.wait(watchdog_interval):
                try:
                    self.watchdog_once()
                except BaseException:
                    # Every uncertain operation is already quarantined in its
                    # ledger. Keep enforcing other leases after one failed stop.
                    continue
        self._watchdog_thread = threading.Thread(target=monitor, name="hf2l-node-watchdog", daemon=True)
        self._watchdog_thread.start()

    def close(self):
        self._watchdog_stop.set()
        self._watchdog_thread.join(timeout=65)
        if self._watchdog_thread.is_alive():
            raise UncertainExecution("Local watchdog has not stopped")
        self._db.close()

    def _allow_launch(self, identity):
        try:
            with self.lock:
                row = self._row(identity)
                return self._lease_valid(row) and row["state"] not in ("STOPPED", "QUARANTINED", "RELEASED")
        except ExecutorRefused:
            return False

    @contextmanager
    def _durable_guard(self, kind, key):
        with self._operations_lock:
            mutex = self._operations.setdefault((kind, key), threading.RLock())
        with mutex:
            depths = getattr(self._guard_depth, "depths", {})
            self._guard_depth.depths = depths
            marker = (kind, key)
            if depths.get(marker, 0):
                depths[marker] += 1
                try: yield
                finally: depths[marker] -= 1
                return
            root = Path(self.ledger_path).parent / (Path(self.ledger_path).name + ".guards")
            root.mkdir(mode=0o700, exist_ok=True)
            if root.is_symlink():
                raise ExecutorRefused("Node guard root is unsafe", "unsafe_root")
            descriptor = os.open(root / (kind + "-" + key + ".lock"),
                                 os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise ExecutorRefused("Node operation guard is unsafe", "unsafe_root")
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                depths[marker] = 1
                try: yield
                finally:
                    depths.pop(marker, None)
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally: os.close(descriptor)

    def _operation_lock(self, identity):
        return self._durable_guard("execution", identity.key)

    def _component_lock(self, identity):
        raw = json.dumps([identity.job_id, identity.component_id], separators=(",", ":")).encode()
        return self._durable_guard("component", hashlib.sha256(raw).hexdigest()[:32])

    @contextmanager
    def component_resource_guard(self, identity: ExecutionIdentity):
        """Serialize planning and cleanup of the same component's private paths."""
        with self._component_lock(identity):
            yield

    def confirm_absent(self, identity: ExecutionIdentity) -> bool:
        """Require positive executor proof; a missing node row alone is insufficient."""
        with self._component_lock(identity):
            with self._operation_lock(identity):
                with self.lock:
                    if self._db.execute("SELECT 1 FROM executions WHERE execution_key=?", (identity.key,)).fetchone():
                        return False
                    if self._db.execute(
                        "SELECT 1 FROM executions WHERE job_id=? AND component_id=? AND state!='RELEASED'",
                        (identity.job_id, identity.component_id)).fetchone():
                        return False
                proof = getattr(self.executor, "confirm_absent", None)
                if proof is None:
                    return False
                try: return proof(identity) is True
                except (ExecutorRefused, UncertainExecution, OSError, ValueError):
                    return False

    def component_purge_allowed(self, identity: ExecutionIdentity) -> bool:
        """Advisory check; use the guard to exclude new reservations during deletion."""
        with self.lock:
            self._row(identity, allow_stale=True)
            rows = self._db.execute(
                "SELECT state FROM executions WHERE job_id=? AND component_id=?",
                (identity.job_id, identity.component_id)).fetchall()
            return bool(rows) and all(row["state"] == "RELEASED" for row in rows)

    @contextmanager
    def component_purge_guard(self, identity: ExecutionIdentity):
        """Hold across node-local deletion and purge so a later epoch cannot race."""
        with self._component_lock(identity):
            if not self.component_purge_allowed(identity):
                raise ExecutorRefused("Component has an unreleased execution", "runtime_active")
            yield

    @contextmanager
    def _storage_transaction(self):
        with self.lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def _storage_usage(self):
        local = self._db.execute(
            "SELECT COALESCE(SUM(CASE WHEN disk_released=1 THEN 0 "
            "ELSE disk_bytes*2+? END +auxiliary_bytes),0) disk FROM executions",
            (EXECUTION_STORAGE_HEADROOM_BYTES,)).fetchone()["disk"]
        shared = self._db.execute("SELECT COALESCE(SUM(reserved_bytes),0) FROM shared_auxiliary").fetchone()[0]
        return local + shared

    def storage_usage_bytes(self) -> int:
        with self.lock: return self._storage_usage()

    def charge_auxiliary_bytes(self, identity: ExecutionIdentity, total_bytes: int) -> bool:
        """Durably reserve peak private config/secret bytes before writing them."""
        if type(total_bytes) is not int or total_bytes < 0:
            raise ExecutorRefused("Invalid auxiliary storage reservation", "invalid_resources")
        with self._storage_transaction():
            row = self._row(identity)
            if row["state"] in ("RELEASED", "STOPPED", "QUARANTINED") or row["disk_released"]:
                raise ExecutorRefused("Assignment cannot add node-local storage", "invalid_execution_state")
            if total_bytes <= row["auxiliary_bytes"]:
                return True
            if self._storage_usage() + total_bytes - row["auxiliary_bytes"] > self.capacity.disk_bytes:
                raise ExecutorRefused("Insufficient physical node storage for approved inputs", "capacity")
            self._db.execute("UPDATE executions SET auxiliary_bytes=? WHERE execution_key=?",
                             (total_bytes, identity.key))
            return True

    def charge_shared_auxiliary_bytes(self, identity: ExecutionIdentity, total_bytes: int) -> bool:
        """Reserve source/build peak once per component across later attempts."""
        if type(total_bytes) is not int or total_bytes < 0:
            raise ExecutorRefused("Invalid shared storage reservation", "invalid_resources")
        with self._storage_transaction():
            row = self._row(identity)
            if row["state"] in ("RELEASED", "STOPPED", "QUARANTINED") or row["disk_released"]:
                raise ExecutorRefused("Assignment cannot add shared input storage", "invalid_execution_state")
            shared = self._db.execute(
                "SELECT reserved_bytes FROM shared_auxiliary WHERE job_id=? AND component_id=?",
                (identity.job_id, identity.component_id)).fetchone()
            previous = shared["reserved_bytes"] if shared else 0
            if total_bytes <= previous: return True
            if self._storage_usage() + total_bytes - previous > self.capacity.disk_bytes:
                raise ExecutorRefused("Insufficient physical node storage for shared inputs", "capacity")
            self._db.execute("INSERT INTO shared_auxiliary VALUES(?,?,?) ON CONFLICT(job_id,component_id) "
                             "DO UPDATE SET reserved_bytes=excluded.reserved_bytes",
                             (identity.job_id, identity.component_id, total_bytes))
            return True

    def assignment_resources(self, identity, *, allow_stale: bool = False):
        with self.lock:
            row = self._row(identity, allow_stale=allow_stale)
            return {"cpu_millicores": row["cpu_millis"],
                    "memory_bytes": row["memory_bytes"], "disk_bytes": row["disk_bytes"]}

    def _row(self, identity: ExecutionIdentity, *, allow_stale: bool = False):
        row = self._db.execute("SELECT * FROM executions WHERE execution_key=?", (identity.key,)).fetchone()
        if not row:
            raise ExecutorRefused("No local acknowledged assignment", "missing_reservation")
        fence = self._db.execute("SELECT epoch FROM fences WHERE job_id=? AND component_id=?",
                                 (identity.job_id, identity.component_id)).fetchone()
        if not allow_stale and (not fence or fence["epoch"] != identity.epoch):
            raise ExecutorRefused("Execution epoch has been fenced", "stale_epoch")
        return row

    def _identity(self, row):
        return ExecutionIdentity(row["job_id"], row["attempt_id"], row["component_id"], row["epoch"])

    def reserve(self, spec: ExecutionSpec) -> Reservation:
        with self._component_lock(spec.identity):
            with self._operation_lock(spec.identity):
                return self._reserve(spec)

    def _reserve(self, spec: ExecutionSpec) -> Reservation:
        if spec.node_id and spec.node_id != self.node_id:
            raise ExecutorRefused("Assignment targets another node", "node_mismatch")
        if spec.pool_id and spec.pool_id != self.pool_id:
            raise ExecutorRefused("Assignment targets another pool", "pool_mismatch")
        if spec.deadline is not None and self.wall_clock() >= spec.deadline:
            raise ExecutorRefused("Job deadline expired", "job_deadline_expired")
        qualify = getattr(self.executor, "qualify_health", None)
        if qualify is not None:
            qualify()
        serialized = json.dumps(asdict(spec), sort_keys=True, separators=(",", ":"))
        with self.lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                prior = self._db.execute("SELECT * FROM executions WHERE execution_key=?", (spec.identity.key,)).fetchone()
                if prior:
                    if prior["spec"] != serialized:
                        raise ExecutorRefused("Reservation identity payload changed", "reservation_conflict")
                    self._row(spec.identity)
                    if prior["state"] == "QUARANTINED":
                        raise ExecutorRefused("Reservation effect requires confirmed cleanup", "node_quarantined")
                    if prior["state"] != "RESERVING":
                        self._db.execute("COMMIT")
                        return Reservation(spec.identity, True, self.node_id, prior["state"])
                    if not self._lease_valid(prior):
                        raise ExecutorRefused("Pending reservation lease expired", "lease_expired")
                else:
                    fence = self._db.execute("SELECT epoch FROM fences WHERE job_id=? AND component_id=?",
                        (spec.identity.job_id, spec.identity.component_id)).fetchone()
                    if fence and spec.identity.epoch <= fence["epoch"]:
                        raise ExecutorRefused("Execution epoch is stale", "stale_epoch")
                    existing = self._db.execute("SELECT 1 FROM executions WHERE job_id=? AND component_id=? AND state!='RELEASED'",
                        (spec.identity.job_id, spec.identity.component_id)).fetchone()
                    if existing:
                        raise ExecutorRefused("Previous component termination/release not confirmed", "node_quarantined")
                    used = self._db.execute("SELECT COALESCE(SUM(CASE WHEN state!='RELEASED' THEN cpu_millis ELSE 0 END),0) cpu,"
                        "COALESCE(SUM(CASE WHEN state!='RELEASED' THEN memory_bytes ELSE 0 END),0) mem FROM executions").fetchone()
                    storage_bytes = self._storage_usage()
                    request = spec.resources
                    if (used["cpu"] + request.cpu_millis > self.capacity.cpu_millis or
                        used["mem"] + request.memory_bytes > self.capacity.memory_bytes or
                        storage_bytes + execution_storage_budget_bytes(request.disk_bytes) > self.capacity.disk_bytes):
                        raise ExecutorRefused("Insufficient locally approved capacity", "capacity")
                    self._db.execute("INSERT INTO fences VALUES(?,?,?) ON CONFLICT(job_id,component_id) DO UPDATE SET epoch=excluded.epoch",
                        (spec.identity.job_id, spec.identity.component_id, spec.identity.epoch))
                    self._db.execute("INSERT INTO executions(execution_key,job_id,attempt_id,component_id,epoch,spec,state,"
                        "cpu_millis,memory_bytes,disk_bytes,lease_until,deadline,boot_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (spec.identity.key, spec.identity.job_id, spec.identity.attempt_id, spec.identity.component_id,
                         spec.identity.epoch, serialized, "RESERVING", request.cpu_millis, request.memory_bytes,
                         request.disk_bytes, self.clock() + spec.lease_seconds, spec.deadline, self.boot_id))
                # Intent, capacity, epoch and identity are durable BEFORE any
                # executor filesystem/runtime side effect can occur.
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        try:
            result = self.executor.reserve(spec)
            if not result.acknowledged:
                raise UncertainExecution("Executor reservation is not acknowledged")
            with self.lock:
                row = self._row(spec.identity)
                if row["state"] != "RESERVING" or not self._lease_valid(row):
                    raise ExecutorRefused("Reservation was fenced or its lease expired", "lease_expired")
                self._db.execute("UPDATE executions SET state='RESERVED' WHERE execution_key=?", (spec.identity.key,))
        except BaseException:
            with self.lock:
                self._db.execute("UPDATE executions SET state='QUARANTINED' WHERE execution_key=?", (spec.identity.key,))
            raise
        return Reservation(spec.identity, True, self.node_id)

    acknowledge = reserve

    def _lease_valid(self, row):
        return (row["boot_id"] == self.boot_id and self.clock() < row["lease_until"]
                and (row["deadline"] is None or self.wall_clock() < row["deadline"]))

    def renew(self, identity: ExecutionIdentity, lease_seconds: float = 120):
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, (int, float)) or not 0 < lease_seconds <= 300:
            raise ExecutorRefused("Lease exceeds permitted lifetime", "invalid_lease")
        with self.lock:
            row = self._row(identity)
            if row["state"] in ("QUARANTINED", "STOPPED", "RELEASED") or not self._lease_valid(row):
                raise ExecutorRefused("Expired execution cannot be revived", "lease_expired")
            self._db.execute("UPDATE executions SET lease_until=? WHERE execution_key=?",
                             (self.clock() + lease_seconds, identity.key))
        return True

    def start(self, identity: ExecutionIdentity) -> RuntimeObservation:
        with self._operation_lock(identity):
            with self.lock:
                row = self._row(identity)
                if not self._lease_valid(row):
                    raise ExecutorRefused("Execution lease expired", "lease_expired")
                if row["state"] not in ("RESERVED", "RUNNING", "STARTING"):
                    raise ExecutorRefused("Assignment is not startable", "invalid_execution_state")
                self._db.execute("UPDATE executions SET state='STARTING' WHERE execution_key=?", (identity.key,))
            try:
                observed = self.executor.start(identity)
            except BaseException:
                with self.lock:
                    self._db.execute("UPDATE executions SET state='QUARANTINED' WHERE execution_key=?", (identity.key,))
                raise
            with self.lock:
                self._db.execute("UPDATE executions SET state=? WHERE execution_key=?", (observed.state, identity.key))
                valid = self._lease_valid(self._row(identity))
            if not valid:
                self.stop(identity, grace_seconds=0)
                raise ExecutorRefused("Lease expired while runtime was starting", "lease_expired")
            return observed

    def inspect(self, identity: ExecutionIdentity) -> RuntimeObservation:
        with self.lock:
            row = self._row(identity)
            if row["executor_absent"]:
                return RuntimeObservation(identity, row["state"], True, details={"never_reserved": True})
        try:
            return self.executor.inspect(identity)
        except ExecutorRefused as exc:
            if exc.code == "missing_reservation" and row["state"] == "RESERVING":
                return RuntimeObservation(identity, "RESERVING", False)
            raise
        except UncertainExecution:
            with self.lock:
                self._db.execute("UPDATE executions SET state='QUARANTINED' WHERE execution_key=?", (identity.key,))
            raise

    def stop(self, identity: ExecutionIdentity, grace_seconds: int = 60) -> RuntimeObservation:
        with self._operation_lock(identity):
            with self.lock:
                row = self._row(identity)
                if row["state"] == "RELEASED" or row["executor_absent"]:
                    return self.inspect(identity)
                self._db.execute("UPDATE executions SET state='STOPPING' WHERE execution_key=?", (identity.key,))
            absent = False
            try:
                try:
                    observed = self.executor.stop(identity, grace_seconds=grace_seconds)
                except ExecutorRefused as exc:
                    proof = getattr(self.executor, "confirm_absent", None)
                    if exc.code != "missing_reservation" or proof is None or proof(identity) is not True:
                        raise
                    absent = True
                    observed = RuntimeObservation(identity, "STOPPED", True, details={"never_reserved": True})
                if not observed.termination_confirmed:
                    raise UncertainExecution("Node stop was not confirmed")
            except BaseException:
                with self.lock:
                    self._db.execute("UPDATE executions SET state='QUARANTINED' WHERE execution_key=?", (identity.key,))
                raise
            with self.lock:
                self._db.execute("UPDATE executions SET state='STOPPED',stopped=1,executor_absent=? WHERE execution_key=?", (int(absent), identity.key))
            return observed

    def reconciliation_root(self, identity: ExecutionIdentity):
        with self.lock: self._row(identity)
        return self.executor.reconciliation_root(identity)

    def retained_manifest(self, identity: ExecutionIdentity):
        with self.lock:
            row = self._row(identity, allow_stale=True)
            if row["state"] != "RELEASED":
                self._row(identity)
            if row["disk_released"]:
                return ()
        return self.executor.collect(identity)

    def read_logs(self, identity: ExecutionIdentity, offset: int = 0, max_bytes: int = 65536):
        with self._operation_lock(identity):
            with self.lock:
                row = self._row(identity, allow_stale=True)
                if row["state"] != "RELEASED": self._row(identity)
                if row["disk_released"]:
                    raise ExecutorRefused("Execution logs were purged", "artifact_unavailable")
                if row["executor_absent"]:
                    if offset != 0:
                        raise ExecutorRefused("Log cursor exceeds an empty execution", "log_cursor_conflict")
                    return {"identity": asdict(identity), "source_id": identity.key, "offset": 0,
                            "next_offset": 0, "content": "", "complete": True, "truncated": False}
            return self.executor.read_logs(identity, offset=offset, max_bytes=max_bytes)

    def read_artifact(self, identity: ExecutionIdentity, path: str, max_bytes: int = 64 * 1024 * 1024) -> bytes:
        with self._operation_lock(identity):
            with self.lock:
                row = self._row(identity, allow_stale=True)
                if row["state"] != "RELEASED": self._row(identity)
                if row["disk_released"]:
                    raise ExecutorRefused("Artifact storage was purged", "artifact_unavailable")
            self.collect(identity)
            return self.executor.read_artifact(identity, path, max_bytes)

    def collect(self, identity: ExecutionIdentity):
        with self._operation_lock(identity):
            with self.lock:
                row = self._row(identity, allow_stale=True)
                if row["state"] != "RELEASED": self._row(identity)
                if row["disk_released"] or row["executor_absent"]: return ()
            if not row["stopped"]:
                observed = self.inspect(identity)
                if not observed.termination_confirmed:
                    raise ExecutorRefused("Active workload cannot be collected", "runtime_active")
            files = self.executor.collect(identity)
            actual = sum(item.size_bytes for item in files)
            if actual > row["disk_bytes"] + EXECUTION_STORAGE_HEADROOM_BYTES:
                raise ExecutorRefused("Collected outputs exceed reserved retention headroom", "retention_capacity")
            with self.lock:
                self._db.execute("UPDATE executions SET retained_output_bytes=? WHERE execution_key=?", (actual, identity.key))
            return files

    def release(self, identity: ExecutionIdentity) -> bool:
        with self._operation_lock(identity):
            with self.lock:
                row = self._row(identity)
                if row["state"] == "RELEASED": return True
            observed = self.inspect(identity)
            if not observed.termination_confirmed:
                raise UncertainExecution("Cannot release active/unknown workload")
            if observed.state not in ("RESERVED", "PREPARING"):
                self.collect(identity)
            if not row["executor_absent"] and not self.executor.release(identity):
                raise UncertainExecution("Runtime resource cleanup is unconfirmed")
            with self.lock:
                self._db.execute("UPDATE executions SET state='RELEASED',stopped=1 WHERE execution_key=?", (identity.key,))
            return True

    def purge(self, identity: ExecutionIdentity, *, auxiliary_deleted: bool = False) -> bool:
        with self._component_lock(identity):
            return self._purge(identity, auxiliary_deleted=auxiliary_deleted)

    def _purge(self, identity: ExecutionIdentity, *, auxiliary_deleted: bool = False) -> bool:
        """Release retained disk only after owned storage deletion is confirmed."""
        with self._operation_lock(identity):
            with self.lock:
                row = self._row(identity, allow_stale=True)
                if row["state"] != "RELEASED":
                    raise ExecutorRefused("Cannot purge an active assignment", "runtime_active")
                shared = self._db.execute(
                    "SELECT reserved_bytes FROM shared_auxiliary WHERE job_id=? AND component_id=?",
                    (identity.job_id, identity.component_id)).fetchone()
                shared_bytes = shared["reserved_bytes"] if shared else 0
                if row["disk_released"] and not shared_bytes: return True
                if (row["auxiliary_bytes"] or shared_bytes) and not auxiliary_deleted:
                    raise ExecutorRefused("Node-local input cleanup is unconfirmed", "auxiliary_storage_retained")
                if auxiliary_deleted and not self.component_purge_allowed(identity):
                    raise ExecutorRefused("Shared input has an unreleased component execution", "runtime_active")
            if not row["executor_absent"] and not self.executor.purge(identity):
                raise UncertainExecution("Retained disk deletion is unconfirmed")
            with self._storage_transaction():
                self._db.execute("UPDATE executions SET disk_released=1,auxiliary_bytes=0 WHERE execution_key=?", (identity.key,))
                if auxiliary_deleted:
                    self._db.execute("UPDATE shared_auxiliary SET reserved_bytes=0 WHERE job_id=? AND component_id=?",
                                     (identity.job_id, identity.component_id))
            return True

    def watchdog_once(self) -> tuple[ExecutionIdentity, ...]:
        """Expired assignments are stopped; compute remains ledger-charged."""
        expired = []
        with self.lock:
            rows = self._db.execute("SELECT * FROM executions WHERE state NOT IN ('RELEASED','STOPPED')").fetchall()
        for row in rows:
            if self._lease_valid(row): continue
            identity = self._identity(row)
            expired.append(identity)
            try: self.stop(identity, grace_seconds=0)
            except (ExecutorRefused, UncertainExecution):
                with self.lock:
                    self._db.execute("UPDATE executions SET state='QUARANTINED' WHERE execution_key=?", (identity.key,))
        return tuple(expired)

    def inventory(self):
        with self.lock:
            return tuple(dict(row) for row in self._db.execute(
                "SELECT execution_key,job_id,attempt_id,component_id,epoch,state,cpu_millis,memory_bytes,disk_bytes,"
                "lease_until,deadline,boot_id,stopped,disk_released,retained_output_bytes,auxiliary_bytes FROM executions ORDER BY execution_key"))

def create_node_app(agent: NodeAgent, authenticate):
    """Authenticated internal endpoint factory. No public/insecure fallback."""
    if authenticate is None:
        raise ExecutorRefused("Node API requires execution-grant authentication", "authentication_required")
    from fastapi import FastAPI, Request, HTTPException
    from starlette.concurrency import run_in_threadpool
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    async def authorize(request, scope, identity):
        if inspect_module.iscoroutinefunction(authenticate):
            principal = await authenticate(request, scope)
        else:
            principal = await run_in_threadpool(authenticate, request, scope)
        if inspect_module.isawaitable(principal): principal = await principal
        expected = {"node_id": agent.node_id, "pool_id": agent.pool_id, **asdict(identity)}
        if any(getattr(principal, name, None) != value for name, value in expected.items()):
            raise HTTPException(403, "Execution grant is not bound to this assignment")
        return principal
    async def payload(request):
        body = await request.json()
        if not isinstance(body, dict): raise HTTPException(422, "Structured assignment required")
        return body
    @app.post("/internal/nodes/v1/reserve")
    async def reserve(request: Request):
        body = await payload(request)
        data = body.get("spec", body)
        try:
            data = dict(data)
            data["identity"] = ExecutionIdentity(**data["identity"])
            data["resources"] = ResourceLimits(**data["resources"])
            data["argv"] = tuple(data["argv"])
            spec = ExecutionSpec(**data)
            principal = await authorize(request, "reserve", spec.identity)
            resources = getattr(principal, "resources", {})
            expected = {"cpu_millicores": spec.resources.cpu_millis,
                        "memory_bytes": spec.resources.memory_bytes,
                        "disk_bytes": spec.resources.disk_bytes}
            if any(resources.get(key) != value for key, value in expected.items()) or resources.get("gpu_uuids"):
                raise HTTPException(403, "Execution resources differ from the node grant")
            return asdict(await run_in_threadpool(agent.reserve, spec))
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(422, "Invalid execution specification") from exc
    for operation in ("start", "inspect", "stop", "collect", "release", "renew", "purge"):
        def make_endpoint(name):
            async def endpoint(request: Request):
                body = await payload(request)
                try: identity = ExecutionIdentity(**body["identity"])
                except (KeyError, TypeError, ValueError) as exc:
                    raise HTTPException(422, "Invalid execution identity") from exc
                principal = await authorize(request, name, identity)
                if name in ("start", "renew"):
                    expected = agent.assignment_resources(identity)
                    resources = getattr(principal, "resources", {})
                    if any(resources.get(key) != value for key, value in expected.items()) or resources.get("gpu_uuids"):
                        raise HTTPException(403, "Execution resources differ from the node grant")
                kwargs = {}
                if name == "stop": kwargs["grace_seconds"] = body.get("grace_seconds", 60)
                if name == "renew": kwargs["lease_seconds"] = body.get("lease_seconds", 120)
                result = await run_in_threadpool(getattr(agent, name), identity, **kwargs)
                if hasattr(result, "__dataclass_fields__"): return asdict(result)
                if isinstance(result, (tuple, list)):
                    return [asdict(item) if hasattr(item, "__dataclass_fields__") else item for item in result]
                return {"confirmed": result}
            return endpoint
        app.add_api_route("/internal/nodes/v1/" + operation, make_endpoint(operation), methods=["POST"])
    @app.post("/internal/nodes/v1/logs")
    async def logs(request: Request):
        body = await payload(request)
        try: identity = ExecutionIdentity(**body["identity"])
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(422, "Invalid execution identity") from exc
        await authorize(request, "logs", identity)
        try:
            return await run_in_threadpool(agent.read_logs, identity,
                offset=body.get("offset", 0), max_bytes=body.get("max_bytes", 65536))
        except ValueError as exc:
            raise HTTPException(422, "Invalid execution log range") from exc
    @app.exception_handler(ExecutorRefused)
    async def refused(request, exc):
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": {"code": exc.code, "message": str(exc)}}, status_code=409)
    @app.exception_handler(UncertainExecution)
    async def uncertain(request, exc):
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": {"code": exc.code, "message": str(exc)}}, status_code=503)
    return app
