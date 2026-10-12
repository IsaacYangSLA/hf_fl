"""Central, current-allocation authorization for registered managed nodes.

Only this control-plane service has manager DB, CA and signing-key access.
Nodes retain their identity/execution private keys and submit public CSRs.
"""
from __future__ import annotations

import base64
import hashlib
import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sqlalchemy import select

from .broker import BrokerError, NodePrincipal, principal_id, stable_workload_principal
from .certificates import CertificateError, CertificateIssuer
from .domain import Error, JobSpec, TERMINAL_STATES, validate_identifier
from .executor import ExecutionIdentity, ExecutorRefused
from .models import Allocation, Attempt, Job, Pool, ProvisioningResource
from .resources import ResourceError, ResourceLedger, stable_key
from .scheduler import LIVE_ALLOCATION_STATES

SharedCertificateIssuer = CertificateIssuer

ACTIVE_STATES = frozenset({"PROVISIONING", "STARTING", "RUNNING"})
_CONTROL_SCOPES = frozenset({"reserve", "start", "inspect", "stop", "release", "renew",
                             "collect", "logs", "assignment", "heartbeat", "purge"})
_NODE_SCOPES = frozenset({"assignment", "acknowledge", "heartbeat", "progress", "logs", "stopped"})
_SAFE_OLD_SCOPES = frozenset({"inspect", "stop", "release", "collect", "logs", "heartbeat"})


def _thumbprint(value):
    try:
        if not isinstance(value, str) or len(value) != 43:
            raise ValueError()
        decoded = base64.urlsafe_b64decode(value + "=")
        if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
            raise ValueError()
        return value
    except (ValueError, TypeError):
        raise Error(422, "invalid_node_certificate") from None


def certificate_thumbprint(certificate_file):
    """Read only an operator-selected public registration certificate."""
    try:
        path = Path(certificate_file)
        if not path.is_absolute() or any(item.is_symlink() for item in (path, *path.parents)):
            raise ValueError()
        if not path.is_file() or path.stat().st_size > 16384:
            raise ValueError()
        cert = x509.load_pem_x509_certificate(path.read_bytes())
        return base64.urlsafe_b64encode(hashlib.sha256(
            cert.public_bytes(serialization.Encoding.DER)).digest()).decode().rstrip("=")
    except (OSError, ValueError, TypeError):
        raise ValueError("Registered node certificate is unavailable or invalid") from None


@dataclass(frozen=True)
class ApprovedManagedNode:
    node_id: str
    pool_id: str
    certificate_thumbprint: str
    registration_id: str
    enabled: bool = True

    def __post_init__(self):
        for value in (self.node_id, self.pool_id, self.registration_id):
            validate_identifier(value)
        _thumbprint(self.certificate_thumbprint)
        if type(self.enabled) is not bool:
            raise ValueError("Node registration enabled must be a Boolean")


class NodeAssignmentService:
    def __init__(self, database, provisioner, broker, registered_nodes, issuer=None, *,
                 certificate_issuer=None, manager_certificate_thumbprint=None, clock=time.time):
        self.database, self.provisioner, self.broker = database, provisioner, broker
        self.issuer = issuer or certificate_issuer
        self.clock = clock
        self.manager_certificate_thumbprint = (
            _thumbprint(manager_certificate_thumbprint) if manager_certificate_thumbprint else None)
        if not isinstance(registered_nodes, Mapping):
            raise ValueError("Managed nodes require an explicit operator registration map")
        nodes = {}
        for node_id, definition in registered_nodes.items():
            if isinstance(definition, ApprovedManagedNode):
                node = definition
            elif isinstance(definition, Mapping):
                try:
                    fingerprint = definition.get("certificate_thumbprint")
                    if fingerprint is None:
                        fingerprint = certificate_thumbprint(definition["certificate_file"])
                    node = ApprovedManagedNode(node_id, definition["pool_id"], fingerprint,
                                               definition["registration_id"], definition.get("enabled", True))
                except (KeyError, TypeError):
                    raise ValueError("Node registration requires node, pool, certificate and registration ID") from None
            else:
                raise ValueError("Invalid managed node registration")
            if node.node_id != node_id:
                raise ValueError("Registered node key and identity differ")
            nodes[node_id] = node
        if len({node.certificate_thumbprint for node in nodes.values()}) != len(nodes):
            raise ValueError("Registered node identity certificates must be distinct")
        if self.manager_certificate_thumbprint in {node.certificate_thumbprint for node in nodes.values()}:
            raise ValueError("Manager and registered node identity certificates must be distinct")
        self.nodes = nodes
        self.ledger = ResourceLedger(database)

    def now(self):
        value = self.clock()
        value = value.timestamp() if hasattr(value, "timestamp") else value
        if type(value) not in (int, float) or not math.isfinite(value):
            raise ValueError("Invalid manager clock")
        return float(value)

    @staticmethod
    def _limits(allocation):
        return {name: getattr(allocation, name)
                for name in ("cpu_millicores", "memory_bytes", "disk_bytes")}

    def _registration(self, node_id, pool_id):
        node = self.nodes.get(node_id)
        if node is None or not node.enabled or node.pool_id != pool_id:
            raise Error(404, "node_assignment_not_found")
        return node

    def _lookup(self, session, identity, node_id=None, pool_id=None, *, lock=False):
        locked_job = (session.scalar(select(Job).where(Job.id == identity.job_id).with_for_update()
            .execution_options(populate_existing=True)) if lock else None)
        query = select(Allocation).where(
            Allocation.job_id == identity.job_id, Allocation.attempt_id == identity.attempt_id,
            Allocation.component_id == identity.component_id, Allocation.epoch == identity.epoch)
        if pool_id is not None:
            query = query.where(Allocation.pool_id == pool_id)
        if lock:
            query = query.with_for_update().execution_options(populate_existing=True)
        allocation = session.scalar(query)
        job, attempt = locked_job or session.get(Job, identity.job_id), session.get(Attempt, identity.attempt_id)
        pool = session.get(Pool, allocation.pool_id) if allocation is not None else None
        if (allocation is None or job is None or attempt is None or pool is None
                or attempt.job_id != job.id or attempt.epoch != identity.epoch
                or allocation.state not in {*LIVE_ALLOCATION_STATES, "RELEASED"}):
            raise Error(404, "node_assignment_not_found")
        owned_node = (allocation.details_json or {}).get("node_id")
        if owned_node is None:
            if allocation.released_at is not None or allocation.state == "RELEASED":
                raise Error(404, "node_assignment_not_found")
            owned_node = pool.node_id
        if node_id is not None and owned_node != node_id:
            raise Error(404, "node_assignment_not_found")
        node = self._registration(owned_node, pool.id)
        configured_registration = (allocation.details_json or {}).get("registration_id")
        if configured_registration is None and pool.node_id == node.node_id:
            configured_registration = (pool.details_json or {}).get("registration_id")
        if configured_registration is not None and configured_registration != node.registration_id:
            raise Error(404, "node_assignment_not_found")
        try:
            spec = JobSpec.model_validate(job.spec_json)
            component = next(item for item in spec.components if item.component_id == identity.component_id)
        except (ValueError, StopIteration):
            raise Error(404, "node_assignment_not_found") from None
        if (job.spec_hash != spec.digest or component.resources.pool_id != pool.id
                or allocation.gpu_count != component.resources.gpu_count
                or self._limits(allocation) != {name: getattr(component.resources, name)
                    for name in ("cpu_millicores", "memory_bytes", "disk_bytes")}):
            raise Error(404, "node_assignment_not_found")
        return job, attempt, allocation, pool, spec, component, node

    @staticmethod
    def _identity(actor):
        try:
            return ExecutionIdentity(actor.job_id, actor.attempt_id, actor.component_id, actor.epoch)
        except (ValueError, AttributeError, ExecutorRefused):
            raise Error(401, "invalid_node_access_token") from None

    def _current(self, job, attempt, allocation):
        return (job.epoch == attempt.epoch == allocation.epoch
                and job.current_attempt == attempt.number
                and job.state in ACTIVE_STATES and allocation.state in LIVE_ALLOCATION_STATES
                and job.deadline_at is not None and job.deadline_at.timestamp() > self.now())

    @staticmethod
    def _pool_current(pool, node):
        registration = (pool.details_json or {}).get("registration_id")
        return pool.node_id == node.node_id and registration in (None, node.registration_id)

    def _require_active(self, session, data, *, acknowledgement=True):
        job, attempt, allocation, pool, spec, component, node = data
        if (not self._current(job, attempt, allocation) or not pool.healthy or pool.quarantined
                or not self._pool_current(pool, node)):
            raise Error(409, "node_assignment_not_ready")
        if acknowledgement:
            allocations = list(session.scalars(select(Allocation).where(
                Allocation.job_id == job.id, Allocation.attempt_id == attempt.id,
                Allocation.epoch == attempt.epoch)))
            if ({item.component_id for item in allocations} != {item.component_id for item in spec.components}
                    or any(not item.acknowledged for item in allocations)):
                raise Error(409, "node_assignment_not_acknowledged")

    def _actor(self, session, actor, *, active=False, node_only=False, lock=False):
        identity = self._identity(actor)
        data = self._lookup(session, identity, actor.node_id, actor.pool_id, lock=lock)
        job, attempt, allocation, pool, spec, component, node = data
        if actor.grant_id != allocation.id or dict(actor.resources) != self._limits(allocation):
            raise Error(401, "invalid_node_access_token")
        if node_only and actor.certificate_thumbprint != node.certificate_thumbprint:
            raise Error(401, "invalid_node_access_token")
        if actor.certificate_thumbprint not in {node.certificate_thumbprint, self.manager_certificate_thumbprint}:
            raise Error(401, "invalid_node_access_token")
        if active:
            self._require_active(session, data)
        return data

    def check_node_grant(self, actor):
        """Validate the current durable allocation, never a signature alone."""
        try:
            with self.database.transaction(immediate=False) as session:
                data = self._actor(session, actor)
                job, attempt, allocation, pool, spec, component, node = data
                scopes = frozenset(actor.scopes)
                if not scopes:
                    return False
                if actor.certificate_thumbprint == node.certificate_thumbprint:
                    # Historical assignment tokens can only introspect stop/cleanup
                    # grants; every source/credential method requires active ACKs.
                    return scopes <= _NODE_SCOPES
                if actor.certificate_thumbprint != self.manager_certificate_thumbprint:
                    return False
                allowed = set(_SAFE_OLD_SCOPES)
                if (self._current(job, attempt, allocation) and pool.healthy and not pool.quarantined
                        and self._pool_current(pool, node)):
                    allowed |= set(_CONTROL_SCOPES) - {"purge"}
                    if not allocation.acknowledged:
                        allowed.discard("start")
                    if "start" in scopes:
                        self._require_active(session, data)
                if (job.state in TERMINAL_STATES and allocation.state == "RELEASED"
                        and allocation.termination_confirmed
                        and job.cleanup_status in {"purge_pending", "expiry_pending"}):
                    allowed.add("purge")
                return scopes <= allowed
        except (Error, ValueError, TypeError, AttributeError):
            return False

    def authenticate_node(self, authorization, *, verified_peer_thumbprint):
        try:
            return self.broker.authenticate_node(
                authorization, verified_peer_thumbprint=verified_peer_thumbprint,
                grant_validator=self.check_node_grant)
        except BrokerError as error:
            raise Error(error.status, error.code) from None

    def bootstrap(self, verified_peer_thumbprint, *, job_id, attempt_id, component_id, epoch):
        """Registered mTLS only; mint a short current-assignment credential."""
        fingerprint = _thumbprint(verified_peer_thumbprint)
        matched = next((node for node in self.nodes.values()
                        if node.enabled and node.certificate_thumbprint == fingerprint), None)
        if matched is None:
            raise Error(401, "unregistered_node_certificate")
        identity = ExecutionIdentity(job_id, attempt_id, component_id, epoch)
        with self.database.transaction(immediate=False) as session:
            data = self._lookup(session, identity, matched.node_id, matched.pool_id)
            job, attempt, allocation, pool, spec, component, node = data
            limits = self._limits(allocation)
            grant_id = allocation.id
        token = self.broker.issue_node(
            node_id=node.node_id, pool_id=node.pool_id, job_id=identity.job_id,
            attempt_id=identity.attempt_id, component_id=identity.component_id, epoch=identity.epoch,
            grant_id=grant_id, certificate_thumbprint=fingerprint, scopes=["assignment"],
            resources=limits, ttl_seconds=300)
        return {"token": token, "expires_at": int(self.now()) + 300}

    def issue_control_token(self, identity, *, node_id, pool_id, scope,
                            certificate_thumbprint=None, resources=None):
        """Trusted manager RPC adapter; issue only ledger-permitted operations."""
        if isinstance(identity, Mapping):
            identity = ExecutionIdentity(**identity)
        fingerprint = certificate_thumbprint or self.manager_certificate_thumbprint
        if fingerprint is None or fingerprint != self.manager_certificate_thumbprint:
            raise Error(401, "invalid_manager_certificate")
        if scope not in _CONTROL_SCOPES:
            raise Error(403, "node_scope_required")
        with self.database.transaction(immediate=False) as session:
            data = self._lookup(session, identity, node_id, pool_id)
            job, attempt, allocation, pool, spec, component, node = data
            limits = self._limits(allocation)
            if resources is not None and dict(resources) != limits:
                raise Error(403, "node_resource_binding_mismatch")
            actor = NodePrincipal(
                principal_id(self.broker.settings.workload_issuer, "node:" + node.node_id),
                "node:" + node.node_id, node.node_id, pool.id, job.id, attempt.id,
                component.component_id, allocation.id, attempt.epoch, fingerprint,
                frozenset({scope}), limits, int(self.now()), int(self.now()) + 300)
        if not self.check_node_grant(actor):
            raise Error(409, "node_operation_not_currently_authorized")
        return self.broker.issue_node(
            node_id=actor.node_id, pool_id=actor.pool_id, job_id=actor.job_id,
            attempt_id=actor.attempt_id, component_id=actor.component_id, epoch=actor.epoch,
            grant_id=actor.grant_id, certificate_thumbprint=fingerprint,
            scopes=[scope], resources=limits, ttl_seconds=300)

    def validate(self, actor, *, node_id, pool_id, grant_id, certificate_thumbprint,
                 scopes, resources):
        """Node introspection of a manager RPC token after local JWT/TLS checks."""
        if "assignment" not in actor.scopes:
            raise Error(403, "node_scope_required")
        with self.database.transaction(immediate=False) as session:
            self._actor(session, actor, node_only=True)
        if (node_id != actor.node_id or pool_id != actor.pool_id or grant_id != actor.grant_id
                or certificate_thumbprint != self.manager_certificate_thumbprint
                or not isinstance(scopes, (list, tuple, set, frozenset))):
            return {"valid": False}
        candidate = NodePrincipal(actor.id, actor.subject, node_id, pool_id, actor.job_id,
            actor.attempt_id, actor.component_id, grant_id, actor.epoch, certificate_thumbprint,
            frozenset(scopes), resources, actor.issued_at, actor.expires_at)
        return {"valid": self.check_node_grant(candidate)}

    def assignment(self, actor):
        if "assignment" not in actor.scopes:
            raise Error(403, "node_scope_required")
        with self.database.transaction(immediate=False) as session:
            job, attempt, allocation, pool, spec, component, node = self._actor(
                session, actor, active=True, node_only=True)
            session.expunge_all()
        document = self.provisioner.prepared_component(job, attempt, component.component_id)
        if (document.get("job_id") != actor.job_id or document.get("attempt_id") != actor.attempt_id
                or document.get("component_id") != actor.component_id or document.get("epoch") != actor.epoch):
            raise Error(503, "prepared_assignment_binding_mismatch")
        try:
            if component.role == "build":
                from .build import BuildConfig
                validated = BuildConfig.model_validate(document)
            else:
                from .workflow import RuntimeConfig
                validated = RuntimeConfig.model_validate(document)
            if validated.source_dir != "/job/source" or validated.state_dir != "/job/state":
                raise ValueError()
            if component.role != "build":
                if validated.proxy_socket != "/run/hf2l/proxy.sock" or validated.exchange_endpoint != "http://proxy":
                    raise ValueError()
            if validated.spec.digest != spec.digest:
                raise ValueError()
            return validated.model_dump(mode="json")
        except ValueError:
            raise Error(503, "prepared_assignment_contains_unapproved_inputs") from None

    def issue_certificate(self, actor, *, csr_pem, space_id, principal_id):
        if "assignment" not in actor.scopes:
            raise Error(403, "node_scope_required")
        if self.issuer is None:
            raise Error(503, "execution_certificate_issuer_unavailable")
        if not isinstance(csr_pem, str) or not 1 <= len(csr_pem.encode("utf-8")) <= 16384:
            raise Error(422, "invalid_execution_csr")
        with self.database.transaction(immediate=False) as session:
            job, attempt, allocation, pool, spec, component, node = self._actor(
                session, actor, active=True, node_only=True)
            if component.role == "build":
                raise Error(403, "build_execution_has_no_workload_credentials")
            expected_space = self.provisioner._space_id(job.id)
            expected_principal = stable_workload_principal(
                self.broker.settings.workload_issuer, job.id, component.component_id, component.participant_id)
            if space_id != expected_space or principal_id != expected_principal or not expected_space:
                raise Error(403, "foreign_execution_certificate_binding")
            deadline = job.deadline_at.timestamp()
        from .certificates import validate_csr
        try:
            validate_csr(csr_pem)
        except CertificateError:
            raise Error(422, "invalid_execution_csr") from None
        identity = self._identity(actor)
        csr_hash = hashlib.sha256(csr_pem.encode("utf-8")).hexdigest()
        try:
            receipt = self.ledger.run(
                job_id=job.id, attempt_id=attempt.id, component_id=component.component_id,
                operation="managed_client_certificate",
                key=stable_key("managed-client-certificate", identity.key),
                desired={"job_id": job.id, "attempt_id": attempt.id,
                    "component_id": component.component_id, "epoch": attempt.epoch,
                    "node_id": node.node_id, "space_id": space_id, "principal_id": principal_id,
                    "csr_hash": csr_hash, "deadline": deadline},
                action=lambda: self.issuer.issue(csr_pem, identity=identity, space_id=space_id, deadline=deadline))
        except CertificateError:
            raise Error(503, "execution_certificate_issuer_unavailable") from None
        except ResourceError:
            raise Error(409, "execution_certificate_binding_immutable") from None
        fingerprint = _thumbprint(receipt.get("certificate_thumbprint"))
        if not isinstance(receipt.get("certificate_pem"), str):
            raise Error(503, "invalid_execution_certificate_receipt")
        # Recheck admission after the external signing boundary before activation.
        with self.database.transaction(immediate=False) as session:
            self._actor(session, actor, active=True, node_only=True)
        self.ledger.own(job_id=job.id, attempt_id=attempt.id, component_id=component.component_id,
            kind="execution_certificate", external_id=identity.key,
            details={**receipt, "csr_hash": csr_hash, "space_id": space_id,
                     "principal_id": principal_id, "epoch": attempt.epoch, "node_id": node.node_id})
        return dict(receipt)

    def credentials(self, actor, *, certificate_thumbprint, audience):
        if "assignment" not in actor.scopes:
            raise Error(403, "node_scope_required")
        if audience not in {"exchange", "gateway"}:
            raise Error(422, "invalid_workload_audience")
        fingerprint = _thumbprint(certificate_thumbprint)
        with self.database.transaction(immediate=False) as session:
            job, attempt, allocation, pool, spec, component, node = self._actor(
                session, actor, active=True, node_only=True)
            if component.role == "build":
                raise Error(403, "build_execution_has_no_workload_credentials")
            identity = self._identity(actor)
            certificate = session.scalar(select(ProvisioningResource).where(
                ProvisioningResource.job_id == job.id, ProvisioningResource.attempt_id == attempt.id,
                ProvisioningResource.component_id == component.component_id,
                ProvisioningResource.kind == "execution_certificate",
                ProvisioningResource.external_id == identity.key, ProvisioningResource.state == "ready"))
            grant = session.scalar(select(ProvisioningResource).where(
                ProvisioningResource.job_id == job.id, ProvisioningResource.attempt_id == attempt.id,
                ProvisioningResource.component_id == component.component_id,
                ProvisioningResource.kind == "workload_grant", ProvisioningResource.state == "ready"))
            if certificate is None or grant is None:
                raise Error(409, "workload_grant_not_ready")
            if certificate.details_json.get("certificate_thumbprint") != fingerprint:
                raise Error(403, "foreign_execution_certificate_binding")
            grant_document = dict(grant.details_json)
            expected = {
                "job_id": job.id, "attempt_id": attempt.id, "component_id": component.component_id,
                "epoch": attempt.epoch, "space_id": certificate.details_json["space_id"],
                "principal_id": certificate.details_json["principal_id"],
                "certificate_thumbprint": fingerprint,
            }
        current = self.provisioner.exchange.request(
            "GET", self.provisioner.exchange.path(expected["space_id"],
                "/workload-grants/" + grant_document["grant_id"]))
        if (any(current.get(key) != value for key, value in expected.items())
                or current.get("grant_id") != grant_document["grant_id"]
                or current.get("enabled") is not True
                or type(current.get("expires_at")) not in (int, float)
                or not math.isfinite(current["expires_at"])
                or current["expires_at"] <= self.now()):
            raise Error(401, "workload_grant_revoked")
        ttl = min(300, int(current["expires_at"] - self.now()), int(job.deadline_at.timestamp() - self.now()))
        if ttl < 1:
            raise Error(401, "workload_grant_revoked")
        # Serialize the final mint with cancellation after the network receipt.
        with self.database.transaction() as session:
            self._actor(session, actor, active=True, node_only=True, lock=True)
            token = self.broker.issue_workload(
                job_id=job.id, attempt_id=attempt.id, component_id=component.component_id,
                space_id=expected["space_id"], grant_id=current["grant_id"], epoch=attempt.epoch,
                certificate_thumbprint=fingerprint, participant_id=component.participant_id,
                audience=audience, ttl_seconds=ttl)
        return {"token": token, "expires_at": int(self.now()) + ttl}

    def check_registration(self, principal):
        try:
            node = self._registration(principal.node_id, principal.pool_id)
            return (principal.registration_id == node.registration_id
                    and principal.certificate_thumbprint == self.manager_certificate_thumbprint
                    and principal.scopes == frozenset({"qualify"}))
        except (Error, ValueError, AttributeError):
            return False

    def issue_platform_token(self, *, node_id, pool_id, registration_id,
                             certificate_thumbprint=None):
        node = self._registration(node_id, pool_id)
        fingerprint = certificate_thumbprint or self.manager_certificate_thumbprint
        if registration_id != node.registration_id or not fingerprint or fingerprint != self.manager_certificate_thumbprint:
            raise Error(403, "node_registration_required")
        return self.broker.issue_node_platform(node_id=node_id, pool_id=pool_id,
            registration_id=registration_id, certificate_thumbprint=fingerprint, ttl_seconds=300)
