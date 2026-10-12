"""Actual build ledger, node quota and opaque chunk transport qualification."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from hf2l_jobs import models
from hf2l_jobs.domain import Error, JobSpec
from hf2l_jobs.execution_proxy import start_mtls_server
from hf2l_jobs.executor import ExecutionIdentity, ExecutorRefused, ResourceLimits
from hf2l_jobs.node_agent import NodeAgent
from hf2l_jobs.participant_build import ExternalBuild, stage_products, CHUNK_BYTES
from hf2l_jobs.participants import ExternalManagerClient
from hf2l_jobs.provisioning import Provisioner
from hf2l_jobs.remote_node import RemoteAssignment, RemoteNodeMaterializer
from hf2l_jobs.resources import ResourceError
from test_gateway import certificate_bundle
from test_participants import ExternalParticipantFixture
from test_remote_node import RecordingRuntime


class BuildFixture(ExternalParticipantFixture):
    def spec(self):
        document = super().spec()
        document["components"].append({"component_id": "build", "role": "build", "resources": {
            "pool_id": "cpu", "cpu_millicores": 1000, "memory_bytes": 1 << 30, "disk_bytes": 1 << 30}})
        return document

    def setUp(self):
        super().setUp()
        self.provisioner = Provisioner(self.database, self.exchange, self.provisioner.registry,
            self.provisioner.root, workload_issuer=self.broker.settings.workload_issuer)
        self.service.provisioner = self.provisioner
        self.enrollment = self.enroll()
        self.activate()
        self.actor, self.bootstrap = self.node_actor(self.enrollment)
        # Intentionally invalid as a ZIP: transport never inspects wheel contents.
        self.payload = b"opaque untrusted wheel; never import or inspect\n" * 4000
        self.filename = "approved_package-1.0-py3-none-any.whl"
        self.artifacts = {self.filename: {"sha256": hashlib.sha256(self.payload).hexdigest(),
                                          "size_bytes": len(self.payload)}}
        self.products = self.provisioner.root / self.job["id"] / "build-products"
        self.products.mkdir(mode=0o700)
        (self.products / self.filename).write_bytes(self.payload)
        with self.database.transaction(immediate=False) as session:
            row = session.get(models.Job, self.job["id"])
            spec = JobSpec.model_validate(row.spec_json)
        self.resource_id = self.provisioner.ledger.own(job_id=self.job["id"],
            attempt_id=self.actor.attempt_id, component_id="owner", kind="build_products",
            external_id=str(self.products), retained=True,
            details={"artifacts": self.artifacts, "spec_digest": spec.digest,
                     "pool_id": "cpu", "size_bytes": len(self.payload)})
        self.build = ExternalBuild(self.service)

    def set_state(self, state):
        with self.database.transaction() as session:
            session.get(models.Job, self.job["id"]).state = state


class ExternalBuildAuthorizationTests(BuildFixture):
    def test_real_build_ledger_exposes_only_immutable_bounded_artifact_identities(self):
        self.assertEqual(self.build.manifest(self.actor), self.artifacts)
        stream = self.build.open_product(self.actor, self.filename)
        self.assertEqual((stream.sha256, stream.size_bytes),
                         (self.artifacts[self.filename]["sha256"], len(self.payload)))
        self.assertEqual(b"".join(stream.chunks()), self.payload)
        self.assertTrue(stream.content.closed)

    def test_scope_is_required_before_any_build_product_read(self):
        self.provisioner.build_manifest = lambda job: self.fail("unauthorized ledger read")
        self.assert_error(403, "node_scope_required", self.build.manifest,
                          replace(self.actor, scopes=frozenset({"heartbeat"})))

    def test_foreign_job_and_current_epoch_are_checked_before_files(self):
        self.provisioner.build_manifest = lambda job: self.fail("foreign ledger read")
        for actor in (replace(self.actor, job_id="foreign-job"), replace(self.actor, epoch=2)):
            self.assert_error(404, "participant_assignment_not_found", self.build.manifest, actor)

    def test_cancelled_job_cannot_retrieve_manifest_or_bytes(self):
        self.set_state("CANCELLING")
        self.assert_error(404, "participant_assignment_not_found", self.build.manifest, self.actor)
        self.assert_error(404, "participant_assignment_not_found", self.build.open_product, self.actor, self.filename)

    def test_expired_node_grant_cannot_read_even_if_job_remains_running(self):
        actor = replace(self.actor, expires_at=int(self.now.timestamp()) - 1)
        self.assert_error(401, "node_grant_expired", self.build.manifest, actor)

    def test_current_node_and_dataset_approval_remain_required(self):
        with self.database.transaction() as session:
            session.get(models.ParticipantBinding, "data-alice").enabled = False
        self.assert_error(403, "external_node_not_approved", self.build.manifest, self.actor)

    def test_missing_build_ledger_is_not_ready_and_never_reads_unowned_wheel(self):
        with self.database.transaction() as session:
            session.delete(session.get(models.ProvisioningResource, self.resource_id))
        self.assert_error(409, "external_build_not_ready", self.build.open_product, self.actor, self.filename)

    def test_ledger_cannot_substitute_a_foreign_job_directory(self):
        with self.database.transaction() as session:
            row = session.get(models.ProvisioningResource, self.resource_id)
            row.external_id = str(self.provisioner.root / "foreign" / "build-products")
        self.assert_error(409, "external_build_not_ready", self.build.manifest, self.actor)

    def test_unapproved_or_path_encoded_filenames_never_select_host_files(self):
        for name in ("../secret.whl", "/secret.whl", "other.whl", "%2e%2e%2fsecret.whl",
                     "a\\b.whl", self.filename + "?token=secret"):
            with self.subTest(filename=name):
                self.assert_error(404, "participant_build_product_not_found",
                                  self.build.open_product, self.actor, name)

    def test_changed_wheel_bytes_and_forged_ledger_digest_are_refused(self):
        (self.products / self.filename).write_bytes(b"forged")
        self.assert_error(409, "external_build_not_ready", self.build.manifest, self.actor)
        (self.products / self.filename).write_bytes(self.payload)
        with self.database.transaction() as session:
            row = session.get(models.ProvisioningResource, self.resource_id)
            row.details_json = {**row.details_json, "artifacts": {
                self.filename: {"sha256": "a" * 64, "size_bytes": len(self.payload)}}}
        self.assert_error(409, "external_build_not_ready", self.build.manifest, self.actor)

    def test_wheel_links_are_refused_by_real_safe_collector(self):
        file = self.products / self.filename
        file.unlink()
        outside = self.root / "outside.whl"
        outside.write_bytes(self.payload)
        file.symlink_to(outside)
        self.assert_error(409, "external_build_not_ready", self.build.manifest, self.actor)

    def test_wheel_hardlinks_are_refused_by_real_safe_collector(self):
        import os
        os.link(self.products / self.filename, self.root / "linked-wheel.whl")
        self.assert_error(409, "external_build_not_ready", self.build.manifest, self.actor)

    def test_stream_rechecks_cancel_and_closes_after_first_chunk(self):
        stream = self.build.open_product(self.actor, self.filename)
        chunks = stream.chunks()
        self.assertEqual(len(next(chunks)), CHUNK_BYTES)
        self.set_state("CANCELLING")
        self.assert_error(404, "participant_assignment_not_found", next, chunks)
        self.assertTrue(stream.content.closed)

    def test_stream_rechecks_token_expiry(self):
        from datetime import timedelta
        stream = self.build.open_product(self.actor, self.filename)
        chunks = stream.chunks()
        next(chunks)
        self.now += timedelta(seconds=301)
        self.assert_error(404, "participant_assignment_not_found", next, chunks)
        self.assertTrue(stream.content.closed)


class ExternalBuildNodeTests(BuildFixture):
    def setUp(self):
        super().setUp()
        self.identity = ExecutionIdentity(self.actor.job_id, self.actor.attempt_id,
                                          self.actor.component_id, self.actor.epoch)
        # The tiny fixture repository has explicit central approval bounds.
        # Use the actual authoritative plan; never enlarge node capacity to
        # hide missing production source or metadata reservations.
        with self.database.transaction() as session:
            approved = session.get(models.ApprovedSource, "source")
            approved.details_json = {**approved.details_json,
                "max_bytes": 1 << 20, "max_files": 128,
                "max_git_bytes": 1 << 20, "max_git_files": 128}
        self.provisioner.ledger.own(job_id=self.job["id"],
            attempt_id=self.actor.attempt_id, component_id="owner", kind="exchange_space",
            external_id="space-" + self.job["id"], retained=True,
            details={"job_id": self.job["id"], "profile": "fedavg.v1"})
        self.approved_plan = self.service.assignment_plan(self.actor)
        root = self.root / "external-node-private"
        runtime = RecordingRuntime(root)
        self.node_agent = NodeAgent(runtime, root / "node.sqlite", "external-node", "external",
            ResourceLimits(4000, 8 << 30, 4 << 30), watchdog_interval=60)
        self.addCleanup(self.node_agent.close)
        self.materializer = RemoteNodeMaterializer(root / "inputs", self.provisioner.registry,
            node_id="external-node", pool_id="external",
            auxiliary_reserver=self.node_agent.charge_auxiliary_bytes,
            require_source_limits=True)
        with self.database.transaction(immediate=False) as session:
            row = session.get(models.Job, self.job["id"])
            self.specification = JobSpec.model_validate(row.spec_json)
        self.assignment = RemoteAssignment(self.identity, "external-node", "external",
            ResourceLimits(500, 128 << 20, 256 << 20), self.specification,
            "sha256:" + "b" * 64, external_participant_id="alice",
            source_limits=self.approved_plan["source_limits"])
        execution = self.materializer.plan(self.assignment)
        self.node_agent.reserve(execution)
        self.materializer.reserve(self.assignment)
        self.requests = []
        self.response_factory = lambda request: httpx.Response(200,
            headers={"Content-Length": str(len(self.payload))}, stream=httpx.ByteStream(self.payload))
        def handler(request):
            self.requests.append(request)
            return self.response_factory(request)
        self.http = httpx.Client(transport=httpx.MockTransport(handler))
        self.addCleanup(self.http.close)
        self.client = ExternalManagerClient("https://manager.example.test", http=self.http)
        self.agent = SimpleNamespace(materializer=self.materializer, node=self.node_agent, client=self.client)

    def staged_file(self):
        return self.materializer.root / "jobs" / self.job["id"] / "components" / self.identity.component_id / "build-inputs" / self.filename

    def test_real_materializer_stages_verified_opaque_chunks_and_durable_node_charge(self):
        self.assertEqual(stage_products(self.agent, self.identity, self.bootstrap["node_token"], self.artifacts),
                         self.artifacts)
        self.assertEqual(self.staged_file().read_bytes(), self.payload)
        self.assertEqual(self.staged_file().stat().st_mode & 0o777, 0o400)
        with self.node_agent.lock:
            row = self.node_agent._db.execute("SELECT auxiliary_bytes FROM executions WHERE execution_key=?",
                (self.identity.key,)).fetchone()
        self.assertEqual(row["auxiliary_bytes"], self.materializer.auxiliary_peak_bytes(
            self.assignment, len(self.payload)))
        self.assertEqual(self.requests[0].method, "GET")
        self.assertEqual(str(self.requests[0].url),
            self.client.endpoint + self.client.prefix(self.identity) + "/build-products/" + self.filename)
        self.assertEqual(self.requests[0].headers["Authorization"], "Bearer " + self.bootstrap["node_token"])
        self.assertEqual(self.requests[0].headers["Accept-Encoding"], "identity")

    def test_idempotent_retry_keeps_exact_final_bytes_and_charge(self):
        first = stage_products(self.agent, self.identity, self.bootstrap["node_token"], self.artifacts)
        self.assertEqual(stage_products(self.agent, self.identity, self.bootstrap["node_token"], self.artifacts), first)
        self.assertEqual(self.staged_file().read_bytes(), self.payload)

    def test_node_capacity_reserved_before_any_http_or_staging(self):
        peak = self.materializer.auxiliary_peak_bytes(self.assignment, len(self.payload))
        self.node_agent.capacity = replace(self.node_agent.capacity,
            disk_bytes=2 * self.assignment.resources.disk_bytes + peak - 1)
        with self.assertRaises(ExecutorRefused) as caught:
            stage_products(self.agent, self.identity, self.bootstrap["node_token"], self.artifacts)
        self.assertEqual(caught.exception.code, "capacity")
        self.assertEqual(self.requests, [])
        self.assertFalse(self.staged_file().exists())

    def test_manifest_disk_limit_and_filename_validated_before_network(self):
        invalid = {"../escape.whl": self.artifacts[self.filename]}
        self.assert_error(422, "invalid_external_build_manifest", stage_products,
                          self.agent, self.identity, self.bootstrap["node_token"], invalid)
        excessive = {self.filename: {"sha256": "a" * 64, "size_bytes": (256 << 20) + 1}}
        self.assert_error(413, "external_build_disk_limit", stage_products,
                          self.agent, self.identity, self.bootstrap["node_token"], excessive)
        self.assertEqual(self.requests, [])

    def test_missing_auxiliary_ledger_fails_before_network(self):
        self.materializer.auxiliary_reserver = None
        self.assert_error(503, "external_build_accounting_unavailable", stage_products,
                          self.agent, self.identity, self.bootstrap["node_token"], self.artifacts)
        self.assertEqual(self.requests, [])

    def test_redirect_and_compression_are_never_followed_or_decoded(self):
        for status, headers, code in ((307, {"Location": "https://foreign.test/wheel"}, "external_manager_redirect_forbidden"),
                                      (200, {"Content-Encoding": "gzip"}, "external_build_invalid_reply")):
            self.response_factory = lambda request: httpx.Response(status, headers=headers, stream=httpx.ByteStream(self.payload))
            self.assert_error(503 if status == 307 else 502, code, stage_products,
                              self.agent, self.identity, self.bootstrap["node_token"], self.artifacts)
            self.assertFalse(self.staged_file().exists())

    def test_content_length_cannot_exceed_or_shrink_immutable_manifest(self):
        for length in (str(len(self.payload) + 1), "-1", "malformed"):
            self.response_factory = lambda request: httpx.Response(200,
                headers={"Content-Length": length}, stream=httpx.ByteStream(self.payload))
            self.assert_error(502, "external_build_size_mismatch", stage_products,
                              self.agent, self.identity, self.bootstrap["node_token"], self.artifacts)
        self.assertFalse(self.staged_file().exists())

    def test_short_transport_can_retry_from_exact_existing_chunks(self):
        class Chunks(httpx.SyncByteStream):
            def __iter__(self):
                yield self_outer.payload[:CHUNK_BYTES]
        self_outer = self
        self.response_factory = lambda request: httpx.Response(200, stream=Chunks())
        self.assert_error(502, "external_build_size_mismatch", stage_products,
                          self.agent, self.identity, self.bootstrap["node_token"], self.artifacts)
        self.assertFalse(self.staged_file().exists())
        self.response_factory = lambda request: httpx.Response(200, stream=httpx.ByteStream(self.payload))
        self.assertEqual(stage_products(self.agent, self.identity, self.bootstrap["node_token"], self.artifacts),
                         self.artifacts)

    def test_oversized_stream_is_refused_without_unbounded_buffering(self):
        self.response_factory = lambda request: httpx.Response(200,
            stream=httpx.ByteStream(self.payload + b"unexpected extra bytes"))
        self.assert_error(502, "external_build_size_mismatch", stage_products,
                          self.agent, self.identity, self.bootstrap["node_token"], self.artifacts)
        self.assertFalse(self.staged_file().exists())

    def test_foreign_execution_identity_is_refused_before_network(self):
        from hf2l_jobs.collection import CollectionError
        with self.assertRaises(CollectionError):
            stage_products(self.agent, replace(self.identity, job_id="foreign-job"),
                           self.bootstrap["node_token"], self.artifacts)
        self.assertEqual(self.requests, [])

    def test_forged_body_never_publishes_wheel(self):
        self.response_factory = lambda request: httpx.Response(200, stream=httpx.ByteStream(b"f" * len(self.payload)))
        with self.assertRaises(ExecutorRefused) as caught:
            stage_products(self.agent, self.identity, self.bootstrap["node_token"], self.artifacts)
        self.assertEqual(caught.exception.code, "unsafe_output")
        self.assertFalse(self.staged_file().exists())

    def test_real_mutual_tls_http_stream_transfers_manager_ledger_bytes(self):
        (self.root / "tls").mkdir()
        bundle = certificate_bundle(self.root / "tls")
        # The approved node TLS fingerprint is updated in both trusted catalogs.
        from hf2l_jobs.participants import ApprovedExternalNode
        self.service.nodes["external-node"] = replace(self.node, certificate_thumbprint=bundle["client"][4])
        with self.database.transaction() as session:
            row = session.get(models.ProvisioningResource, self.enrollment["id"])
            row.details_json = {**row.details_json, "node_certificate_thumbprint": bundle["client"][4]}
            execution = session.get(models.ProvisioningResource, row.details_json["external_execution_id"])
            execution.details_json = {**execution.details_json, "node_certificate_thumbprint": bundle["client"][4]}
        bootstrap = self.service.bootstrap_credentials(self.enrollment["id"])
        app = FastAPI()
        @app.exception_handler(Error)
        async def domain_error(request, error):
            return JSONResponse({"error": {"code": error.code}}, status_code=error.status)
        @app.get("/internal/jobs/v1/participants/{job}/{attempt}/{component}/{epoch}/build-products/{filename}")
        async def product(job: str, attempt: str, component: str, epoch: int, filename: str, request: Request):
            peer = request.scope["state"]["verified_certificate_thumbprint"]
            actor = self.broker.authenticate_node(request.headers.get("Authorization", ""),
                verified_peer_thumbprint=peer, grant_validator=self.service.check_node_grant)
            if (actor.job_id, actor.attempt_id, actor.component_id, actor.epoch) != (job, attempt, component, epoch):
                raise Error(404, "participant_assignment_not_found")
            stream = self.build.open_product(actor, filename)
            return StreamingResponse(stream.chunks(), media_type="application/octet-stream",
                headers={"Content-Length": str(stream.size_bytes)})
        server = start_mtls_server(app, certificate=bundle["server"][2],
            key=bundle["server"][3], client_ca=bundle["ca"][2])
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        client = ExternalManagerClient("https://127.0.0.1:" + str(server.server_address[1]),
            ca_file=bundle["ca"][2], certificate_file=bundle["client"][2], key_file=bundle["client"][3])
        self.addCleanup(client.close)
        self.agent.client = client
        self.assertEqual(stage_products(self.agent, self.identity, bootstrap["node_token"], self.artifacts),
                         self.artifacts)
        self.assertEqual(self.staged_file().read_bytes(), self.payload)


if __name__ == "__main__":
    unittest.main()
