"""Actual manager ACLs, private local files, and mTLS artifact download grants."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
import uuid

from sqlalchemy import delete, select, update

from hf2l_exchange.domain import Error as ExchangeError
from hf2l_exchange.models import WorkloadGrant
from hf2l_jobs.application import Manager
from hf2l_jobs.collection import RetainedFile
from hf2l_jobs.controller import Controller
from hf2l_jobs.database import create_database
from hf2l_jobs.domain import Error as ManagerError
from hf2l_jobs.execution_proxy import start_mtls_server
from hf2l_jobs.executor import ExecutionIdentity
from hf2l_jobs.gateway import GatewayError
from hf2l_jobs.managed_client import ManagedArtifactBroker
from hf2l_jobs.models import Allocation, Artifact, Attempt, Job, JobMember, Pool, Project, ProvisioningResource
from hf2l_jobs.resources import ResourceLedger

from test_gateway import GatewayFixture


class ProvisioningAdapter:
    """Privileged adapter over the actual Exchange service, never workload code."""
    def __init__(self, service, principal):
        self.service, self.principal, self.calls = service, principal, []

    @staticmethod
    def path(space, suffix):
        return "/v2/spaces/" + space + suffix

    def set_member(self, space, principal, roles, *, subject, bindings):
        return self.service.put_member(self.principal, space, principal,
            {"subject": subject, "roles": roles, "bindings": bindings})

    def request(self, method, path, *, body, headers):
        self.calls.append((method, path, dict(body)))
        space = path.split("/")[3]
        if path.endswith("/workload-grants/revoke"):
            return self.service.revoke_workload_grants(self.principal, space, body, headers["Idempotency-Key"])
        if path.endswith("/workload-grants"):
            return self.service.create_workload_grant(self.principal, space, body, headers["Idempotency-Key"])
        raise AssertionError("Unexpected provisioning endpoint " + path)


class ManagedArtifactBrokerTests(GatewayFixture):
    def setUp(self):
        super().setUp()
        self.database = create_database("sqlite:///" + self.directory.name + "/jobs.db")
        self.addCleanup(self.database.close)
        now = datetime.now(timezone.utc)
        with self.database.transaction() as session:
            session.add(Project(id="project-a", name="Project A"))
            session.flush()
            for identity in ("job-a", "job-b"):
                session.add(Job(id=identity, project_id="project-a", creator_id="owner", name=identity,
                    spec_json={}, spec_hash="a" * 64, target_round=1, state="SUCCEEDED",
                    artifacts_expire_at=now + timedelta(hours=1)))
            session.flush()
            session.add(JobMember(job_id="job-a", principal_id="viewer", role="reader"))
        self.manager = Manager(self.database, cursor_secret="test-cursor-signing-secret-at-least-32-bytes",
                               platform_operator_ids=("platform-operator",))
        self.ledger = ResourceLedger(self.database)
        self.ledger.own(job_id="job-a", attempt_id=None, component_id="owner", kind="exchange_space", external_id=self.sid)
        self.root = Path(self.directory.name) / "jobs"
        self.root.mkdir(mode=0o700)
        self.local = self.root / "job-a" / "artifacts"
        self.local.mkdir(mode=0o700, parents=True)
        self.foreign = self.root / "job-b" / "artifacts"
        self.foreign.mkdir(mode=0o700, parents=True)
        self.local_resource = self.ledger.own(job_id="job-a", attempt_id=None, component_id="owner",
            kind="artifact_directory", external_id=str(self.local), retained=True)
        self.foreign_resource = self.ledger.own(job_id="job-b", attempt_id=None, component_id="owner",
            kind="artifact_directory", external_id=str(self.foreign), retained=True)
        self.adapter = ProvisioningAdapter(self.service, self.provisioner)
        self.gateway_server = start_mtls_server(self.app, certificate=self.bundle["server"][2],
            key=self.bundle["server"][3], client_ca=self.bundle["ca"][2])
        self.addCleanup(self.gateway_server.server_close)
        self.addCleanup(self.gateway_server.shutdown)
        self.artifacts = ManagedArtifactBroker(self.manager, self.database, self.adapter, self.broker, self.root,
            client_ca_certificate=self.bundle["ca"][2], client_ca_key=self.bundle["ca"][3],
            gateway_endpoint="https://127.0.0.1:" + str(self.gateway_server.server_address[1]),
            service_ca_file=self.bundle["ca"][2], max_bytes=16)

    def artifact(self, locator, content=b"abcdefgh", name="checkpoint.bin"):
        identity = uuid.uuid4().hex
        with self.database.transaction() as session:
            session.add(Artifact(id=identity, job_id="job-a", kind="checkpoint", name=name,
                size_bytes=len(content), sha256=hashlib.sha256(content).hexdigest(), storage_key="private-test-key",
                locator_json=locator, state="available", expires_at=datetime.now(timezone.utc) + timedelta(minutes=20)))
        return identity

    def exchange_artifact(self):
        return self.artifact({"kind": "exchange", "space_id": self.sid,
                              "record_id": "record-a", "attachment_id": "attachment-a"})

    def local_artifact(self, name="checkpoint.bin", content=b"abcdefgh"):
        (self.local / name).write_bytes(content)
        return self.artifact({"kind": "local", "resource_id": self.local_resource, "relative_path": name}, content=content)

    def read(self, identity, actor="viewer"):
        async def collect():
            async with self.artifacts.open_authorized(actor, "job-a", identity) as opened:
                chunks = [chunk async for chunk in opened.chunks]
                return opened, b"".join(chunks)
        return asyncio.run(collect())

    def grants(self):
        with self.service.sessions() as session:
            return session.scalars(select(WorkloadGrant).where(WorkloadGrant.component_id == "download-broker")).all()

    def test_actual_mtls_download_uses_fresh_private_read_only_job_grants(self):
        identity = self.exchange_artifact()
        for _ in range(2):
            opened, data = self.read(identity)
            self.assertEqual(data, b"abcdefgh")
            self.assertEqual(opened.size, 8)
            self.assertEqual(opened.name, "checkpoint.bin")
        grants = self.grants()
        self.assertEqual(len(grants), 2)
        self.assertNotEqual(grants[0].certificate_thumbprint, grants[1].certificate_thumbprint)
        for grant in grants:
            self.assertEqual(grant.roles, ["reader"])
            self.assertEqual(grant.job_id, "job-a")
            self.assertEqual(grant.space_id, self.sid)
            self.assertLessEqual(grant.expires_at - grant.created_at, 300)
        self.assertEqual(list((self.root / ".artifact-broker" / "job-a").iterdir()), [])
        resources = self.ledger.resources("job-a", kind="workload_grant")
        self.assertEqual(len(resources), 2)
        self.assertTrue(all(item["details"]["roles"] == ["reader"] for item in resources))

    def test_current_acl_is_rechecked_and_platform_role_has_no_content_access(self):
        identity = self.exchange_artifact()
        for actor in ("stranger", "platform-operator"):
            with self.subTest(actor=actor), self.assertRaises(ManagerError) as caught:
                self.read(identity, actor)
            self.assertEqual(caught.exception.status, 404)
        self.assertEqual(self.grants(), [])
        self.assertEqual(self.read(identity)[1], b"abcdefgh")
        with self.database.transaction() as session:
            session.execute(delete(JobMember).where(JobMember.job_id == "job-a", JobMember.principal_id == "viewer"))
        with self.assertRaises(ManagerError) as caught:
            self.read(identity)
        self.assertEqual(caught.exception.status, 404)
        self.assertEqual(len(self.grants()), 1)

    def test_expired_artifact_and_expired_job_deny_before_grant_creation(self):
        identity = self.exchange_artifact()
        with self.database.transaction() as session:
            session.get(Artifact, identity).expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        with self.assertRaises(ManagerError) as caught:
            self.read(identity)
        self.assertEqual(caught.exception.status, 410)
        identity = self.exchange_artifact()
        with self.database.transaction() as session:
            session.get(Job, "job-a").artifacts_expire_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        with self.assertRaises(ManagerError) as caught:
            self.read(identity)
        self.assertEqual(caught.exception.status, 410)
        self.assertEqual(self.grants(), [])

    def test_retention_revoke_is_permanent_fence_against_new_broker_grants(self):
        identity = self.exchange_artifact()
        self.assertEqual(self.read(identity)[1], b"abcdefgh")
        self.assertTrue(self.artifacts.revoke("job-a"))
        self.assertFalse(self.grants()[0].enabled)
        with self.assertRaises(ExchangeError) as caught:
            self.read(identity)
        self.assertEqual(caught.exception.status, 409)
        self.assertTrue(self.artifacts.revoke("job-a"))
        self.assertTrue(all(not grant.enabled for grant in self.grants()))
        self.assertEqual(list((self.root / ".artifact-broker" / "job-a").iterdir()), [])

    def test_local_regular_file_stream_and_download_name_sanitization(self):
        identity = self.local_artifact()
        with self.database.transaction() as session:
            session.get(Artifact, identity).name = "../foreign\r\nX-Header: injected"
        opened, body = self.read(identity)
        self.assertEqual(body, b"abcdefgh")
        self.assertEqual(opened.name, "artifact.bin")
        self.assertEqual(self.adapter.calls, [])
        self.assertEqual(self.grants(), [])

    def test_symlink_hardlink_and_fifo_do_not_expose_foreign_files(self):
        foreign = self.foreign / "secret.bin"
        foreign.write_bytes(b"abcdefgh")
        for kind in ("symlink", "hardlink", "fifo"):
            target = self.local / (kind + ".bin")
            if kind == "symlink":
                target.symlink_to(foreign)
            elif kind == "hardlink":
                os.link(foreign, target)
            else:
                os.mkfifo(target)
            identity = self.artifact({"kind": "local", "resource_id": self.local_resource,
                                      "relative_path": target.name}, content=b"" if kind == "fifo" else b"abcdefgh")
            with self.subTest(kind=kind), self.assertRaises(GatewayError) as caught:
                self.read(identity)
            self.assertEqual(caught.exception.status, 404)
        self.assertEqual(foreign.read_bytes(), b"abcdefgh")

    def test_foreign_resource_and_path_traversal_are_rejected_by_real_manager(self):
        identity = self.artifact({"kind": "local", "resource_id": self.foreign_resource,
                                  "relative_path": "secret.bin"})
        with self.assertRaises(ManagerError) as caught:
            self.read(identity)
        self.assertEqual(caught.exception.status, 503)
        identity = self.local_artifact()
        for path in ("../secret.bin", "/tmp/secret.bin", "nested/../../secret.bin", "nested\\secret.bin"):
            with self.database.transaction() as session:
                session.execute(update(Artifact).where(Artifact.id == identity).values(locator_json={
                    "kind": "local", "resource_id": self.local_resource, "relative_path": path}))
            with self.subTest(path=path), self.assertRaises(ManagerError) as caught:
                self.read(identity)
            self.assertEqual(caught.exception.status, 503)

    def test_resource_ownership_and_deleted_state_rechecked(self):
        identity = self.local_artifact()
        with self.database.transaction() as session:
            resource = session.get(ProvisioningResource, self.local_resource)
            resource.ownership_json = dict(resource.ownership_json, job_id="job-b")
        with self.assertRaises(ManagerError) as caught:
            self.read(identity)
        self.assertEqual(caught.exception.status, 503)
        with self.database.transaction() as session:
            resource = session.get(ProvisioningResource, self.local_resource)
            resource.ownership_json = dict(resource.ownership_json, job_id="job-a")
            resource.state = "cleanup_pending"
        with self.assertRaises(GatewayError) as caught:
            self.read(identity)
        self.assertEqual(caught.exception.status, 404)

    def test_local_digest_mismatch_and_mutation_are_detected(self):
        identity = self.local_artifact()
        (self.local / "checkpoint.bin").write_bytes(b"modified")
        with self.assertRaises(GatewayError) as caught:
            self.read(identity)
        self.assertEqual(caught.exception.status, 502)
        (self.local / "checkpoint.bin").write_bytes(b"abcdefgh")
        async def change_during_stream():
            async with self.artifacts.open_authorized("viewer", "job-a", identity) as opened:
                iterator = opened.chunks.__aiter__()
                self.assertEqual(await iterator.__anext__(), b"abcdefgh")
                with (self.local / "checkpoint.bin").open("ab") as target:
                    target.write(b"changed")
                await iterator.__anext__()
        with self.assertRaises(GatewayError) as caught:
            asyncio.run(change_during_stream())
        self.assertEqual(caught.exception.status, 502)

    def test_exchange_integrity_descriptor_and_size_limit_enforced(self):
        identity = self.exchange_artifact()
        with self.database.transaction() as session:
            session.get(Artifact, identity).sha256 = "0" * 64
        with self.assertRaises(GatewayError) as caught:
            self.read(identity)
        self.assertEqual(caught.exception.status, 409)
        identity = self.local_artifact(content=b"x" * 17)
        with self.assertRaises(GatewayError) as caught:
            self.read(identity)
        self.assertEqual(caught.exception.status, 413)

    def collection_context(self, *, disk_bytes, node_id="test-node"):
        """Persist production allocation fields and the admitted attempt fence."""
        identity = ExecutionIdentity("job-a", "attempt-a", "owner", 1)
        with self.database.transaction() as session:
            if session.get(Attempt, identity.attempt_id) is None:
                session.add(Attempt(id=identity.attempt_id, job_id=identity.job_id,
                                    number=1, epoch=identity.epoch, state="SUCCEEDED"))
                session.flush()
            if session.get(Pool, "pool-a") is None:
                session.add(Pool(id="pool-a", name="Fixture pool", node_id=node_id,
                    cpu_millicores=1000, memory_bytes=1024 * 1024,
                    disk_bytes=64 * 1024 * 1024, healthy=True))
                session.flush()
            job = session.get(Job, identity.job_id)
            job.current_attempt, job.attempt_count, job.epoch = 1, 1, identity.epoch
            attempt = session.get(Attempt, identity.attempt_id)
            allocation = Allocation(id=uuid.uuid4().hex, job_id=identity.job_id,
                attempt_id=identity.attempt_id, component_id=identity.component_id,
                pool_id="pool-a", cpu_millicores=100, memory_bytes=1024,
                disk_bytes=max(16, disk_bytes), gpu_count=0, epoch=identity.epoch,
                state="RELEASED", acknowledged=True, termination_confirmed=True,
                details_json={"node_id": node_id}, released_at=datetime.now(timezone.utc))
            session.add(allocation)
            session.flush()
        return job, attempt, allocation

    def controller_artifact(self, group="state", *, location_identity=None, content=b"abcdefgh", prefixed=False):
        executor_root = Path(self.directory.name) / "executor"
        executor_root.mkdir(mode=0o700, exist_ok=True)
        identity = ExecutionIdentity("job-a", "attempt-a", "owner", 1)
        target_identity = location_identity or identity
        relative = "models/checkpoint.bin" if group == "state" else "container.log"
        destination = executor_root / target_identity.key / "retained" / group / relative
        job, attempt, allocation = self.collection_context(disk_bytes=len(content))
        controller = Controller(self.database, SimpleNamespace(root=executor_root), None)
        controller._reserve_collection(job, attempt, allocation)
        with self.database.transaction(immediate=False) as session:
            self.collection_prepaid_bytes = session.get(Project, "project-a").retained_bytes
        destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        destination.write_bytes(content)
        collected_path = group + "/" + relative if prefixed else relative
        collected = RetainedFile(collected_path, str(destination), len(content), hashlib.sha256(content).hexdigest())
        controller._store_collected(job, attempt, allocation, [collected])
        with self.database.transaction(immediate=False) as session:
            artifact = session.scalar(select(Artifact).where(Artifact.storage_key == str(destination)))
            identity = artifact.id
            resource_id = artifact.locator_json["resource_id"]
        self.artifacts = ManagedArtifactBroker(self.manager, self.database, self.adapter, self.broker, self.root,
            client_ca_certificate=self.bundle["ca"][2], client_ca_key=self.bundle["ca"][3],
            gateway_endpoint="https://127.0.0.1:" + str(self.gateway_server.server_address[1]),
            service_ca_file=self.bundle["ca"][2], executor_root=executor_root, max_bytes=16)
        return identity, resource_id

    def test_controller_generated_retained_state_locator_downloads_from_executor_root(self):
        identity, resource_id = self.controller_artifact("state")
        with self.database.transaction(immediate=False) as session:
            artifact = session.get(Artifact, identity)
            resource = session.get(ProvisioningResource, resource_id)
            self.assertEqual(artifact.state, "retained")
            self.assertEqual(resource.kind, "retained_artifact_root")
            self.assertEqual(resource.ownership_json, {"job_id": "job-a", "attempt_id": "attempt-a",
                "component_id": "owner", "epoch": 1})
            self.assertEqual(artifact.locator_json["relative_path"], "models/checkpoint.bin")
            reservation = session.scalar(select(ProvisioningResource).where(
                ProvisioningResource.kind == "collection_budget", ProvisioningResource.job_id == "job-a"))
            output = session.scalar(select(ProvisioningResource).where(
                ProvisioningResource.kind == "retained_output", ProvisioningResource.job_id == "job-a"))
            prepaid_cap = self.collection_prepaid_bytes
            parent_charge = reservation.details_json["retention_charged_bytes"]
            child_charge = output.details_json["retention_charged_bytes"]
            self.assertEqual(reservation.details_json["retention_reservation_bytes"], prepaid_cap)
            self.assertGreater(parent_charge, 0)
            self.assertEqual(child_charge, 8)
            self.assertEqual(parent_charge + child_charge, prepaid_cap)
            self.assertEqual(reservation.size_bytes, parent_charge)
            self.assertEqual(reservation.details_json["retention_transferred_bytes"], 8)
            self.assertTrue(reservation.details_json["retention_retain_unused"])
            self.assertTrue(reservation.details_json["retention_conservative_footprint"])
            self.assertFalse(reservation.details_json["retention_charge_released"])
            self.assertFalse(output.details_json["retention_charge_released"])
            self.assertEqual(output.details_json["retention_reservation_source"], reservation.id)
            self.assertEqual(session.get(Project, "project-a").retained_bytes, prepaid_cap)
        self.assertEqual(self.read(identity)[1], b"abcdefgh")
        self.assertEqual(self.adapter.calls, [])
        # Downloading cannot release the physical collection bound before purge.
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(session.get(Project, "project-a").retained_bytes, prepaid_cap)
            for resource_id in (reservation.id, output.id):
                stored = session.get(ProvisioningResource, resource_id)
                self.assertFalse(stored.details_json["retention_charge_released"])
                self.assertIsNone(stored.deleted_at)

    def test_controller_generated_retained_runtime_log_downloads_from_executor_root(self):
        identity, _ = self.controller_artifact("runtime", content=b"runtime log")
        self.assertEqual(self.read(identity)[1], b"runtime log")
        self.assertEqual(self.adapter.calls, [])

    def test_retained_root_under_foreign_execution_key_is_denied(self):
        foreign = ExecutionIdentity("job-b", "attempt-b", "owner", 1)
        identity, _ = self.controller_artifact("state", location_identity=foreign)
        with self.assertRaises(GatewayError) as caught:
            self.read(identity)
        self.assertEqual(caught.exception.status, 404)

    def test_retained_root_group_and_epoch_must_match_trusted_execution_ownership(self):
        identity, _ = self.controller_artifact("foreign")
        with self.assertRaises(GatewayError) as caught:
            self.read(identity)
        self.assertEqual(caught.exception.status, 404)
        identity, resource_id = self.controller_artifact("state")
        for field, value in (("epoch", 2), ("attempt_id", "attempt-b"), ("component_id", "participant-b")):
            with self.database.transaction() as session:
                session.get(ProvisioningResource, resource_id).ownership_json = {
                    "job_id": "job-a", "attempt_id": "attempt-a", "component_id": "owner", "epoch": 1, field: value}
            with self.subTest(field=field), self.assertRaises(GatewayError) as caught:
                self.read(identity)
            self.assertEqual(caught.exception.status, 404)

    def test_retained_resource_kind_cannot_adopt_arbitrary_external_path(self):
        identity, resource_id = self.controller_artifact("state")
        with self.database.transaction() as session:
            session.get(ProvisioningResource, resource_id).kind = "owned_directory"
        with self.assertRaises(GatewayError) as caught:
            self.read(identity)
        self.assertEqual(caught.exception.status, 404)

    def test_controller_generated_runtime_prefixed_locator_matches_real_executor_collection(self):
        identity, resource_id = self.controller_artifact("runtime", prefixed=True, content=b"runtime log")
        with self.database.transaction(immediate=False) as session:
            artifact = session.get(Artifact, identity)
            resource = session.get(ProvisioningResource, resource_id)
            self.assertEqual(artifact.locator_json["relative_path"], "runtime/container.log")
            expected = Path(self.directory.name) / "executor" / ExecutionIdentity("job-a", "attempt-a", "owner", 1).key / "retained"
            self.assertEqual(resource.external_id, str(expected))
        self.assertEqual(self.read(identity)[1], b"runtime log")

    def test_retained_parent_root_does_not_authorize_unknown_relative_prefix(self):
        identity, _ = self.controller_artifact("foreign", prefixed=True)
        with self.assertRaises(GatewayError) as caught:
            self.read(identity)
        self.assertEqual(caught.exception.status, 404)


    def remote_controller_artifact(self, *, content=b"abcdefgh", node_id="test-node"):
        """Persist exactly the manifest and node affinity produced by Controller."""
        identity = ExecutionIdentity("job-a", "attempt-a", "owner", 1)
        relative = "runtime/container.log"
        locator = "hf2l-node://" + node_id + "/" + identity.key + "/" + relative
        executor_root = Path(self.directory.name) / "executor"
        executor_root.mkdir(mode=0o700, exist_ok=True)
        job, attempt, allocation = self.collection_context(disk_bytes=len(content), node_id=node_id)
        controller = Controller(self.database, SimpleNamespace(root=executor_root), None)
        controller._reserve_collection(job, attempt, allocation)
        collected = RetainedFile(relative, locator, len(content), hashlib.sha256(content).hexdigest())
        controller._store_collected(job, attempt, allocation, [collected])
        with self.database.transaction(immediate=False) as session:
            artifact = session.scalar(select(Artifact).where(Artifact.storage_key == locator))
            artifact_id = artifact.id
            resource_id = artifact.locator_json["resource_id"]

        class RegisteredRemote:
            def __init__(self):
                self.node_id = node_id
                self.content = content
                self.route_calls = []
                self.read_calls = []

            def route(self, execution_identity, allocation):
                self.route_calls.append((execution_identity, allocation))
                return SimpleNamespace(node_id=self.node_id)

            def read_artifact(self, execution_identity, path, *, max_bytes):
                self.read_calls.append((execution_identity, path, max_bytes))
                return self.content

        remote = RegisteredRemote()
        self.artifacts = ManagedArtifactBroker(
            self.manager, self.database, self.adapter, self.broker, self.root,
            client_ca_certificate=self.bundle["ca"][2], client_ca_key=self.bundle["ca"][3],
            gateway_endpoint="https://127.0.0.1:" + str(self.gateway_server.server_address[1]),
            service_ca_file=self.bundle["ca"][2], executor_root=executor_root,
            remote_executor=remote, max_bytes=max(16, len(content)))
        return artifact_id, resource_id, remote, identity

    def test_controller_remote_retained_artifact_reads_exact_registered_identity_in_bounded_chunks(self):
        content = b"r" * 65537
        artifact_id, resource_id, remote, identity = self.remote_controller_artifact(content=content)
        with self.database.transaction(immediate=False) as session:
            resource = session.get(ProvisioningResource, resource_id)
            self.assertEqual(resource.external_id, "hf2l-node://test-node/" + identity.key)
            self.assertEqual(resource.details_json["node_id"], "test-node")
            self.assertEqual(resource.ownership_json, {"job_id": identity.job_id,
                "attempt_id": identity.attempt_id, "component_id": identity.component_id, "epoch": identity.epoch})
            self.assertEqual(session.get(Artifact, artifact_id).locator_json["relative_path"], "runtime/container.log")

        async def collect():
            async with self.artifacts.open_authorized("viewer", "job-a", artifact_id) as opened:
                self.assertEqual(opened.size, len(content))
                return [chunk async for chunk in opened.chunks]

        chunks = asyncio.run(collect())
        self.assertEqual([len(chunk) for chunk in chunks], [65536, 1])
        self.assertEqual(b"".join(chunks), content)
        self.assertEqual(remote.route_calls, [(identity, None)])
        self.assertEqual(remote.read_calls, [(identity, "runtime/container.log", len(content))])
        self.assertEqual(self.adapter.calls, [])
        self.assertEqual(self.grants(), [])

    def test_remote_missing_or_foreign_affinity_and_uri_identity_deny_before_read(self):
        artifact_id, resource_id, remote, identity = self.remote_controller_artifact()
        original_uri = "hf2l-node://test-node/" + identity.key
        foreign_identity = ExecutionIdentity("job-b", "attempt-b", "owner", 1)
        cases = (
            ("missing-node", {}, original_uri),
            ("foreign-node", {"node_id": "foreign-node"}, original_uri),
            ("foreign-uri", {"node_id": "test-node"}, "hf2l-node://foreign-node/" + identity.key),
            ("foreign-identity", {"node_id": "test-node"}, "hf2l-node://test-node/" + foreign_identity.key),
        )
        for attack, details, uri in cases:
            with self.database.transaction() as session:
                resource = session.get(ProvisioningResource, resource_id)
                resource.details_json = details
                resource.external_id = uri
            with self.subTest(attack=attack), self.assertRaises(GatewayError) as caught:
                self.read(artifact_id)
            self.assertEqual(caught.exception.status, 404)
            self.assertEqual(remote.route_calls, [])
            self.assertEqual(remote.read_calls, [])

    def test_remote_registered_route_must_match_persisted_node_before_read(self):
        artifact_id, resource_id, remote, identity = self.remote_controller_artifact()
        for attack, stored_node, routed_node in (
            ("foreign-route", "test-node", "foreign-node"),
            ("foreign-uri-and-affinity", "foreign-node", "test-node"),
            ("missing-route", "test-node", None),
        ):
            remote.node_id = routed_node
            remote.route_calls.clear()
            with self.database.transaction() as session:
                resource = session.get(ProvisioningResource, resource_id)
                resource.external_id = "hf2l-node://" + stored_node + "/" + identity.key
                resource.details_json = dict(resource.details_json, node_id=stored_node)
            with self.subTest(attack=attack), self.assertRaises(GatewayError) as caught:
                self.read(artifact_id)
            self.assertEqual(caught.exception.status, 404)
            self.assertEqual(remote.route_calls, [(identity, None)])
            self.assertEqual(remote.read_calls, [])

    def test_remote_returned_length_and_hash_are_verified_before_exposing_content(self):
        artifact_id, _, remote, identity = self.remote_controller_artifact()
        for content in (b"short", b"abcdefgh-extra", b"ABCDEFGH"):
            remote.content = content
            remote.read_calls.clear()
            with self.subTest(content=content), self.assertRaises(GatewayError) as caught:
                self.read(artifact_id)
            self.assertEqual(caught.exception.status, 409)
            self.assertEqual(caught.exception.code, "artifact_integrity_failed")
            self.assertEqual(remote.read_calls, [(identity, "runtime/container.log", 8)])


if __name__ == "__main__":
    unittest.main()
