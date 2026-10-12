"""Real mutual-TLS node routing, private materialization, and durable local ACKs."""
from __future__ import annotations

from dataclasses import asdict, replace
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest

import httpx
from fastapi import HTTPException, Request

from hf2l_jobs.broker import BrokerSettings, WorkloadBroker
from hf2l_jobs.collection import CollectionError, SafeCollector, delete_retained
from hf2l_jobs.domain import JobSpec
from hf2l_jobs.execution_proxy import start_mtls_server
from hf2l_jobs.executor import (
    ExecutionIdentity, ExecutionSpec, ExecutorRefused, Reservation, ResourceLimits,
    RuntimeObservation, UncertainExecution,
)
from hf2l_jobs.node_agent import NodeAgent
from hf2l_jobs.remote_node import (
    NodeEndpoint, NodeRoute, RemoteAssignment, RemoteExecutor,
    RemoteNodeMaterializer, create_remote_node_app,
)
from hf2l_jobs.source import RegistryCatalog, SourceApproval, SourceRegistry
from test_gateway import certificate_bundle


class RecordingRuntime:
    """Observe dispatch; production always uses the qualified LinuxExecutor."""
    def __init__(self, root):
        self.root = root
        self.specs, self.states, self.retained = {}, {}, {}
        self.stops = []

    def reserve(self, spec):
        self.specs[spec.identity.key] = spec
        self.states.setdefault(spec.identity.key, "RESERVED")
        return Reservation(spec.identity, True, spec.node_id)

    def start(self, identity):
        spec = self.specs[identity.key]
        assert Path(spec.config_path).is_file()
        assert Path(spec.source_path).is_dir()
        assert Path(spec.state_path).is_dir()
        self.states[identity.key] = "RUNNING"
        return self.inspect(identity)

    def inspect(self, identity):
        state = self.states[identity.key]
        return RuntimeObservation(identity, state, state in {"STOPPED", "RELEASED"})

    def stop(self, identity, grace_seconds=60):
        self.stops.append(identity)
        self.states[identity.key] = "STOPPED"
        return self.inspect(identity)

    def collect(self, identity):
        if identity.key not in self.retained:
            spec = self.specs[identity.key]
            with SafeCollector(spec.state_path) as collector:
                self.retained[identity.key] = collector.retain(self.root / "retained" / identity.key)
        return self.retained[identity.key]

    def retained_manifest(self, identity):
        return self.collect(identity)

    def release(self, identity):
        self.states[identity.key] = "RELEASED"
        return True

    def purge(self, identity):
        return delete_retained(self.root / "retained" / identity.key, self.retained[identity.key])

    def reconciliation_root(self, identity):
        return Path(self.specs[identity.key].state_path)


class RemoteNodeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="hf2l-remote-nodes-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.certificates = certificate_bundle(self.root)
        self.signer = self.certificates["ca"][0]
        self.broker = WorkloadBroker(BrokerSettings(
            "https://workloads.test", "exchange", "gateway", "nodes",
            self.signer.public_key(), self.signer,
        ))
        repository = self.root / "approved-repository"
        repository.mkdir()
        commands = (
            ["git", "init", "-q", str(repository)],
            ["git", "-C", str(repository), "config", "user.email", "synthetic@test.invalid"],
            ["git", "-C", str(repository), "config", "user.name", "Synthetic Test"],
        )
        for command in commands:
            subprocess.run(command, check=True, capture_output=True)
        content = b'raise RuntimeError("control plane imported workload")\n'
        (repository / "dangerous.py").write_bytes(content)
        for command in (
            ["git", "-C", str(repository), "add", "dangerous.py"],
            ["git", "-C", str(repository), "commit", "-qm", "approved input"],
        ):
            subprocess.run(command, check=True, capture_output=True)
        self.commit = subprocess.check_output(
            ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
        ).strip()
        self.manifest = {"dangerous.py": hashlib.sha256(content).hexdigest()}
        self.registry = RegistryCatalog(
            SourceRegistry([SourceApproval("source-a", frozenset({"project-a"}),
                mirror_path=repository / ".git", commits=frozenset({self.commit}))]),
            {"runtime-a": "sha256:" + "1" * 64},
        )
        self.routes, self.jobs, self.nodes, self.endpoints = {}, {}, {}, {}
        self.revoked = False
        self.override_token = None
        self._add_node("node-a", "pool-a", "job-a")
        self.executor = self._executor()
        self.addCleanup(self.executor.close)

    def _job(self, pool):
        return JobSpec.model_validate({
            "project_id": "project-a", "name": "Federated test", "source_id": "source-a",
            "source_commit": self.commit, "runtime_image": "runtime-a", "plugin": "dangerous",
            "components": [{"component_id": "owner", "role": "owner", "resources": {
                "pool_id": pool, "cpu_millicores": 500, "memory_bytes": 128 * 1024**2,
                "disk_bytes": 32 * 1024**2,
            }}],
            "target_round": 1, "max_duration_seconds": 120,
        })

    def _add_node(self, node, pool, job):
        root = self.root / node
        root.mkdir(mode=0o700)
        runtime = RecordingRuntime(root)
        clock = [100.0]
        agent = NodeAgent(runtime, root / "node.sqlite", node, pool,
                          ResourceLimits(2000, 1024**3, 512 * 1024**2),
                          clock=lambda: clock[0], watchdog_interval=60)
        self.addCleanup(agent.close)
        materializer = RemoteNodeMaterializer(root / "private-inputs", self.registry,
                                             node_id=node, pool_id=pool)
        def authenticate(request, scope):
            try:
                return self.broker.authenticate_node(
                    request.headers.get("Authorization", ""),
                    verified_peer_thumbprint=request.scope["state"]["verified_certificate_thumbprint"],
                    grant_validator=lambda principal: not self.revoked and principal.node_id == node
                            and scope in principal.scopes,
                )
            except Exception:
                raise HTTPException(401, "Current node grant required") from None
        app = create_remote_node_app(agent, authenticate, materializer)
        server = start_mtls_server(
            app, certificate=self.certificates["server"][2],
            key=self.certificates["server"][3], client_ca=self.certificates["ca"][2],
        )
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        endpoint = NodeEndpoint(
            node, "https://127.0.0.1:" + str(server.server_address[1]),
            self.certificates["ca"][2], self.certificates["client"][2],
            self.certificates["client"][3], timeout_seconds=3,
        )
        self.endpoints[node] = endpoint
        self.jobs[job] = self._job(pool)
        self.routes[job] = NodeRoute(node, pool, ResourceLimits(500, 128 * 1024**2, 32 * 1024**2))
        self.nodes[node] = (agent, materializer, runtime, clock)

    def _executor(self, **kwargs):
        def assignment(spec, route):
            return RemoteAssignment(spec.identity, route.node_id, route.pool_id, route.resources,
                                    self.jobs[spec.identity.job_id], "sha256:" + "1" * 64)
        return RemoteExecutor(
            self.endpoints, route=lambda identity, pool=None: self.routes[identity.job_id],
            assignment_provider=assignment, token_provider=self.token, **kwargs,
        )

    def token(self, route, identity, scope):
        values = {
            "node_id": route.node_id, "pool_id": route.pool_id, **asdict(identity),
            "grant_id": "grant-" + identity.key, "scopes": [scope],
            "certificate_thumbprint": self.certificates["client"][4],
            "resources": {"cpu_millicores": route.resources.cpu_millis,
                          "memory_bytes": route.resources.memory_bytes,
                          "disk_bytes": route.resources.disk_bytes},
        }
        if self.override_token:
            values.update(self.override_token)
        return self.broker.issue_node(**values)

    def spec(self, job="job-a", epoch=1):
        route = self.routes[job]
        return ExecutionSpec(
            ExecutionIdentity(job, "attempt-" + str(epoch), "owner", epoch), "sha256:" + "1" * 64,
            "/manager/private/source-not-on-node", "/manager/private/state-not-on-node",
            ("python", "-m", "hf2l_jobs.runtime", "--config", "/run/hf2l/runtime.json"),
            "/manager/private/proxy-not-on-node", route.resources, pool_id=route.pool_id,
        )

    def configuration(self, spec):
        job = self.jobs[spec.identity.job_id]
        return {
            "job_id": spec.identity.job_id, "attempt_id": spec.identity.attempt_id,
            "component_id": spec.identity.component_id, "epoch": spec.identity.epoch,
            "role": "owner", "space_id": "space-" + spec.identity.job_id, "spec": job.to_dict(),
            "spec_digest": job.digest, "source_manifest": self.manifest,
        }

    def prepare(self, spec):
        self.assertTrue(self.executor.reserve(spec).acknowledged)
        self.assertTrue(self.executor.prepare(spec.identity, self.configuration(spec)))

    def test_actual_mtls_reserve_materialize_start_stop_retained_download_release(self):
        spec = self.spec()
        self.prepare(spec)
        self.assertEqual(self.executor.start(spec.identity).state, "RUNNING")
        local_spec = self.nodes["node-a"][2].specs[spec.identity.key]
        self.assertTrue(local_spec.source_path.startswith(str(self.root / "node-a")))
        self.assertFalse(Path(local_spec.source_path, ".git").exists())
        self.assertNotIn("dangerous", sys.modules)
        Path(local_spec.state_path, "checkpoint.bin").write_bytes(b"opaque model")
        self.assertTrue(self.executor.stop(spec.identity).termination_confirmed)
        files = self.executor.collect(spec.identity)
        self.assertEqual(files[0].locator, "hf2l-node://node-a/" + spec.identity.key + "/checkpoint.bin")
        self.assertEqual(self.executor.read_artifact(spec.identity, "checkpoint.bin"), b"opaque model")
        self.assertTrue(self.executor.release(spec.identity))
        self.assertEqual(self.executor.read_artifact(spec.identity, "checkpoint.bin"), b"opaque model")
        self.assertTrue(self.executor.purge(spec.identity))

    def test_two_real_tls_listeners_route_to_their_approved_private_nodes(self):
        self._add_node("node-b", "pool-b", "job-b")
        executor = self._executor()
        self.addCleanup(executor.close)
        for job in ("job-a", "job-b"):
            spec = self.spec(job)
            executor.reserve(spec)
            executor.prepare(spec.identity, self.configuration(spec))
            executor.start(spec.identity)
        self.assertEqual(len(self.nodes["node-a"][2].specs), 1)
        self.assertEqual(len(self.nodes["node-b"][2].specs), 1)
        node_a_source = Path(next(iter(self.nodes["node-a"][2].specs.values())).source_path)
        node_b_source = Path(next(iter(self.nodes["node-b"][2].specs.values())).source_path)
        self.assertNotEqual(node_a_source, node_b_source)

    def test_copied_certificate_bound_token_cannot_reserve_with_other_cert(self):
        endpoint = replace(self.endpoints["node-a"], client_certificate=self.certificates["other"][2],
                           client_key=self.certificates["other"][3])
        executor = RemoteExecutor(
            {"node-a": endpoint}, route=self.executor.route,
            assignment_provider=self.executor.assignment_provider, token_provider=self.token,
        )
        self.addCleanup(executor.close)
        with self.assertRaises(ExecutorRefused):
            executor.reserve(self.spec())
        self.assertEqual(self.nodes["node-a"][0].inventory(), ())

    def test_resource_identity_epoch_and_revoked_grants_are_denied(self):
        spec = self.spec()
        for changes in ({"job_id": "another-job"}, {"epoch": 2}, {"resources": {
            "cpu_millicores": 501, "memory_bytes": 128 * 1024**2, "disk_bytes": 32 * 1024**2,
        }}):
            self.override_token = changes
            with self.subTest(changes=changes), self.assertRaises(ExecutorRefused):
                self.executor.reserve(spec)
        self.override_token = None
        self.prepare(spec)
        self.revoked = True
        with self.assertRaises(ExecutorRefused):
            self.executor.start(spec.identity)
        self.assertNotIn("RUNNING", self.nodes["node-a"][2].states.values())

    def test_host_paths_commands_and_unknown_assignment_fields_are_rejected(self):
        spec = self.spec()
        route = self.routes["job-a"]
        document = self.executor.assignment_provider(spec, route).to_dict()
        for field in ("source_path", "state_path", "argv", "mounts", "proxy_endpoint"):
            unsafe = {**document, field: "/another-job/private"}
            with self.subTest(field=field), self.assertRaises(ExecutorRefused):
                self.executor._post(route, spec.identity, "reserve", {"assignment": unsafe})
        self.assertEqual(self.nodes["node-a"][0].inventory(), ())

    def test_changed_preparation_and_foreign_source_manifest_are_rejected(self):
        spec = self.spec()
        self.executor.reserve(spec)
        configuration = self.configuration(spec)
        configuration["source_manifest"] = {"dangerous.py": "0" * 64}
        with self.assertRaises(ExecutorRefused):
            self.executor.prepare(spec.identity, configuration)
        self.executor.prepare(spec.identity, self.configuration(spec))
        configuration = self.configuration(spec)
        configuration["space_id"] = "another-space"
        with self.assertRaises(ExecutorRefused):
            self.executor.prepare(spec.identity, configuration)

    def test_local_watchdog_stops_after_transport_lease_expiry_without_releasing(self):
        spec = self.spec()
        self.prepare(spec)
        self.executor.start(spec.identity)
        agent, _, runtime, clock = self.nodes["node-a"]
        self.assertTrue(self.executor.renew(spec.identity, lease_seconds=120))
        clock[0] += 121
        self.assertEqual(agent.watchdog_once(), (spec.identity,))
        self.assertEqual(runtime.states[spec.identity.key], "STOPPED")
        self.assertNotEqual(agent.inventory()[0]["state"], "RELEASED")
        with self.assertRaises(ExecutorRefused):
            self.executor.renew(spec.identity)

    def test_transport_failure_is_uncertain_without_any_local_fallback(self):
        def failed(request):
            raise httpx.ConnectError("synthetic endpoint unavailable")
        executor = self._executor(client_factory=lambda endpoint: httpx.Client(
            transport=httpx.MockTransport(failed), trust_env=False))
        self.addCleanup(executor.close)
        with self.assertRaises(UncertainExecution):
            executor.reserve(self.spec())
        self.assertEqual(self.nodes["node-a"][0].inventory(), ())

    def test_artifact_traversal_and_live_output_reads_are_rejected(self):
        spec = self.spec()
        self.prepare(spec)
        self.executor.start(spec.identity)
        with self.assertRaises(ExecutorRefused):
            self.executor.read_state(spec.identity, "../other-job")
        self.executor.stop(spec.identity)
        with self.assertRaises(ExecutorRefused):
            self.executor.read_state(spec.identity, "../other-job")
        with self.assertRaises(ExecutorRefused):
            self.executor.read_artifact(spec.identity, "../other-job")

    def test_node_endpoint_requires_fixed_https_and_private_client_key(self):
        endpoint = self.endpoints["node-a"]
        for origin in ("http://localhost:123", "https://user:pass@localhost", "https://localhost/path",
                       "https://localhost?redirect=evil"):
            with self.subTest(origin=origin), self.assertRaises(ExecutorRefused):
                replace(endpoint, origin=origin)
        key = Path(endpoint.client_key)
        key.chmod(0o644)
        with self.assertRaises(ExecutorRefused):
            endpoint.client()

    def test_optional_state_missing_is_none_but_links_and_traversal_are_refused(self):
        import os
        spec = self.spec()
        self.prepare(spec)
        self.executor.stop(spec.identity)
        self.assertIsNone(self.executor.read_state(spec.identity, "initialization.json"))
        local = self.nodes["node-a"][2].specs[spec.identity.key]
        Path(local.state_path, "linked.json").symlink_to(self.root / "outside.json")
        with self.assertRaises(ExecutorRefused):
            self.executor.read_state(spec.identity, "linked.json")
        with self.assertRaises(ExecutorRefused):
            self.executor.read_state(spec.identity, "../initialization.json")

    def _build_job(self):
        document = self.jobs["job-a"].to_dict()
        component = dict(document["components"][0])
        component.update(component_id="build", role="build")
        document["components"].append(component)
        self.jobs["job-a"] = JobSpec.model_validate(document)

    def test_real_tls_verified_wheel_chunks_are_private_opaque_and_idempotent(self):
        self._build_job()
        spec = self.spec()
        payload = b"opaque-not-an-archive\n" * 60000
        filename = "synthetic-1.0-py3-none-any.whl"
        configuration = self.configuration(spec)
        configuration["built_artifacts"] = {filename: {
            "size_bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}}
        self.executor.reserve(spec)
        self.assertTrue(self.executor.prepare(spec.identity, configuration, build_products={filename: payload}))
        local = self.nodes["node-a"][2].specs[spec.identity.key]
        self.assertEqual(Path(local.build_input_path, filename).read_bytes(), payload)
        self.assertEqual(Path(local.build_input_path, filename).stat().st_mode & 0o777, 0o400)
        self.assertTrue(self.executor.prepare(spec.identity, configuration, build_products={filename: payload}))
        self.assertEqual(self.executor.start(spec.identity).state, "RUNNING")
        with self.assertRaises(ExecutorRefused):
            self.executor.prepare(spec.identity, configuration, build_products={filename: b"changed"})
        with self.assertRaises(ExecutorRefused):
            self.executor.prepare(spec.identity, configuration)
        self.executor.stop(spec.identity)
        self.executor.collect(spec.identity)
        self.executor.release(spec.identity)
        self.executor.purge(spec.identity)
        self.assertFalse(Path(local.source_path).exists())
        self.assertFalse(Path(local.build_input_path).exists())

    def test_wheel_upload_rejects_escape_link_oversize_and_changed_chunk(self):
        import base64
        self._build_job()
        spec = self.spec()
        self.executor.reserve(spec)
        materializer = self.nodes["node-a"][1]
        filename = "synthetic-1.0-py3-none-any.whl"
        artifacts = {filename: {"size_bytes": 8, "sha256": hashlib.sha256(b"abcdefgh").hexdigest()}}
        materializer.stage_build_input(spec.identity, artifacts, filename, 0, base64.b64encode(b"abcd").decode())
        with self.assertRaises(ExecutorRefused):
            materializer.stage_build_input(spec.identity, artifacts, filename, 0, base64.b64encode(b"xxxx").decode())
        with self.assertRaises(ExecutorRefused):
            materializer.stage_build_input(spec.identity, artifacts, "../outside.whl", 0, "YQ==")
        too_large = {filename: {"size_bytes": 33 * 1024**2, "sha256": "1"*64}}
        with self.assertRaises(ExecutorRefused):
            materializer.stage_build_input(spec.identity, too_large, filename, 0, "YQ==")
        local = materializer.reserve(materializer.assignment(spec.identity))
        part = Path(local.build_input_path, "." + filename + ".part")
        part.unlink()
        outside = self.root / "outside"
        outside.write_bytes(b"preserved")
        part.symlink_to(outside)
        with self.assertRaises((ExecutorRefused, OSError)):
            materializer.stage_build_input(spec.identity, artifacts, filename, 0, "YWJjZA==")
        self.assertEqual(outside.read_bytes(), b"preserved")

    def test_shared_wheel_charge_covers_blocks_and_rejects_more_than_one_output_per_builder(self):
        import base64
        self._build_job()
        spec = self.spec()
        self.executor.reserve(spec)
        materializer = self.nodes["node-a"][1]
        assignment = materializer.assignment(spec.identity)
        shared, private = [], []
        materializer.shared_auxiliary_reserver = lambda identity, size: shared.append((identity, size))
        materializer.auxiliary_reserver = lambda identity, size: private.append((identity, size))
        baseline = materializer.auxiliary_peak_bytes(assignment)
        filename = "synthetic-1.0-py3-none-any.whl"
        payload = b"x"
        artifact = {"size_bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        materializer.stage_build_input(spec.identity, {filename: artifact}, filename, 0,
                                       base64.b64encode(payload).decode())
        private_bytes = 4 * 1024**2 + 256 * 1024
        self.assertEqual(private, [(spec.identity, private_bytes)])
        self.assertEqual(shared, [(spec.identity, baseline - private_bytes + len(payload) + 8192 * 5)])
        parent = Path(materializer.plan(assignment).build_input_path).parent
        owned_build_bytes = sum(path.stat().st_blocks * 512 for path in (
            parent / "build-inputs", parent / "build-inputs" / filename,
            parent / "build-input-manifest.json"))
        self.assertLessEqual(owned_build_bytes, len(payload) + 8192 * 5)
        extra = "other-1.0-py3-none-any.whl"
        with self.assertRaises(ExecutorRefused):
            materializer.stage_build_input(spec.identity, {filename: artifact, extra: artifact}, extra, 0,
                                           base64.b64encode(payload).decode())
        self.assertFalse((parent / "build-inputs" / extra).exists())
        self.assertEqual(len(shared), 1)

    def test_purge_removes_private_source_and_configs_without_following_escape(self):
        from hf2l_jobs.remote_node import purge_private_tree
        spec = self.spec()
        self.prepare(spec)
        self.executor.stop(spec.identity)
        self.executor.collect(spec.identity)
        self.executor.release(spec.identity)
        materializer = self.nodes["node-a"][1]
        local = materializer.reserve(materializer.assignment(spec.identity))
        parent = Path(local.source_path).parent
        outside = self.root / "outside"
        outside.write_bytes(b"outside safe")
        (parent / "escape").symlink_to(outside)
        with self.assertRaises((ExecutorRefused, CollectionError)):
            self.executor.purge(spec.identity)
        self.assertTrue(Path(local.source_path).is_dir())
        self.assertEqual(outside.read_bytes(), b"outside safe")
        (parent / "escape").unlink()
        self.assertTrue(self.executor.purge(spec.identity))
        self.assertFalse(parent.exists())
        self.assertTrue(self.executor.purge(spec.identity))
        self.assertTrue(purge_private_tree(parent))

    def test_purge_private_tree_rejects_hardlinks_before_deleting_files(self):
        import os
        from hf2l_jobs.remote_node import purge_private_tree
        root = self.root / "private-purge"
        root.mkdir(mode=0o700)
        (root / "first").write_bytes(b"preserve on unsafe inventory")
        outside = self.root / "outside"
        outside.write_bytes(b"outside safe")
        os.link(outside, root / "linked")
        with self.assertRaises(CollectionError):
            purge_private_tree(root)
        self.assertTrue((root / "first").exists())
        self.assertEqual(outside.read_bytes(), b"outside safe")

    def test_slow_prepare_does_not_block_other_job_lease_renewal(self):
        import concurrent.futures
        import threading
        self._add_node("node-b", "pool-b", "job-b")
        # Route a second independent job to the same node so this exercises its
        # ASGI event loop and per-execution locks, not separate listeners.
        self.routes["job-b"] = self.routes["job-a"]
        self.jobs["job-b"] = self._job("pool-a")
        executor = self._executor()
        self.addCleanup(executor.close)
        first, second = self.spec(), self.spec("job-b")
        executor.reserve(first)
        executor.reserve(second)
        materializer = self.nodes["node-a"][1]
        original = materializer.prepare
        entered, release = threading.Event(), threading.Event()
        def slow(*args, **kwargs):
            entered.set()
            release.wait(3)
            return original(*args, **kwargs)
        materializer.prepare = slow
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
            future = workers.submit(executor.prepare, first.identity, self.configuration(first))
            self.assertTrue(entered.wait(1))
            renew = workers.submit(executor.renew, second.identity)
            try:
                self.assertTrue(renew.result(timeout=1))
            finally:
                release.set()
            self.assertTrue(future.result(timeout=3))

    def test_central_credentials_use_fresh_registered_node_bootstrap_over_real_mtls(self):
        from fastapi import FastAPI, Request
        from hf2l_jobs.remote_node import NodeCredentialClient
        app = FastAPI()
        receipts = []
        @app.post("/internal/jobs/v1/nodes/{job}/{attempt}/{component}/{epoch}/bootstrap")
        async def bootstrap(job: str, attempt: str, component: str, epoch: int, request: Request):
            self.assertEqual(request.scope["state"]["verified_certificate_thumbprint"], self.certificates["client"][4])
            self.assertNotIn("authorization", request.headers)
            self.assertEqual(await request.json(), {})
            receipts.append("bootstrap")
            return {"token": "fresh-node-token-" + str(len(receipts)), "expires_at": 1234567890}
        @app.post("/internal/jobs/v1/nodes/{job}/{attempt}/{component}/{epoch}/credentials")
        async def credentials(job: str, attempt: str, component: str, epoch: int, request: Request):
            self.assertTrue(request.headers["authorization"].startswith("Bearer fresh-node-token-"))
            document = await request.json()
            self.assertEqual(document["certificate_thumbprint"], self.certificates["client"][4])
            receipts.append(document["audience"])
            return {"token": "scoped-" + document["audience"]}
        server = start_mtls_server(app, certificate=self.certificates["server"][2],
            key=self.certificates["server"][3], client_ca=self.certificates["ca"][2])
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        endpoint = replace(self.endpoints["node-a"], origin="https://127.0.0.1:" + str(server.server_address[1]))
        client = NodeCredentialClient(endpoint)
        self.addCleanup(client.close)
        identity = self.spec().identity
        self.assertEqual(client.credentials(identity, self.certificates["client"][4], "exchange"), "scoped-exchange")
        self.assertEqual(client.credentials(identity, self.certificates["client"][4], "gateway"), "scoped-gateway")
        self.assertEqual(receipts, ["bootstrap", "exchange", "bootstrap", "gateway"])

    def test_platform_qualification_has_distinct_no_job_authority_and_manager_pin(self):
        from hf2l_jobs.remote_node import NodePlatformClient
        agent, materializer, runtime, _ = self.nodes["node-a"]
        runtime.profile = {"qualified": True, "runtime": "runsc", "network": "none", "bounded_volumes": "loop-ext4"}
        runtime.qualify_health = lambda: True
        def authenticate(request, scope):
            return self.broker.authenticate_node(request.headers.get("authorization", ""),
                verified_peer_thumbprint=request.scope["state"]["verified_certificate_thumbprint"],
                grant_validator=lambda principal: True)
        def qualify_authenticate(request):
            return self.broker.authenticate_node_platform(request.headers.get("authorization", ""),
                verified_peer_thumbprint=request.scope["state"]["verified_certificate_thumbprint"],
                registration_validator=lambda principal: principal.registration_id == "registration-a")
        app = create_remote_node_app(agent, authenticate, materializer,
            qualify_authenticate=qualify_authenticate, registration_id="registration-a",
            manager_certificate_thumbprint=self.certificates["client"][4])
        server = start_mtls_server(app, certificate=self.certificates["server"][2],
            key=self.certificates["server"][3], client_ca=self.certificates["ca"][2])
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        endpoint = replace(self.endpoints["node-a"], origin="https://127.0.0.1:" + str(server.server_address[1]))
        client = NodePlatformClient(endpoint)
        self.addCleanup(client.close)
        token = self.broker.issue_node_platform(node_id="node-a", pool_id="pool-a",
            registration_id="registration-a", certificate_thumbprint=self.certificates["client"][4])
        report = client.qualify("pool-a", "registration-a", token)
        self.assertTrue(report["healthy"])
        self.assertEqual(report["capacity"]["disk_bytes"], agent.capacity.disk_bytes)
        with self.assertRaises(ExecutorRefused):
            client.qualify("pool-a", "different-registration", token)
        with self.assertRaises(ExecutorRefused):
            client.qualify("pool-a", "registration-a", self.token(self.routes["job-a"], self.spec().identity, "heartbeat"))
        with client.http.stream("POST", endpoint.origin + "/internal/nodes/v1/reserve",
                json={"assignment": RemoteAssignment(self.spec().identity, "node-a", "pool-a",
                    self.routes["job-a"].resources, self.jobs["job-a"], "sha256:" + "1"*64).to_dict()},
                headers={"Authorization": "Bearer " + token}) as response:
            self.assertGreaterEqual(response.status_code, 400)

    def test_assignment_plan_creates_no_job_paths_before_durable_reservation(self):
        materializer = self.nodes["node-a"][1]
        spec = self.spec()
        route = self.routes["job-a"]
        assignment = RemoteAssignment(spec.identity, route.node_id, route.pool_id, route.resources,
                                      self.jobs["job-a"], "sha256:" + "1" * 64)
        planned = materializer.plan(assignment)
        self.assertEqual(planned.identity, spec.identity)
        self.assertFalse((materializer.root / "jobs" / spec.identity.job_id).exists())
        self.assertFalse((materializer.assignments / (spec.identity.key + ".json")).exists())
        self.assertTrue(self.executor.reserve(spec).acknowledged)
        self.assertTrue((materializer.assignments / (spec.identity.key + ".json")).is_file())
        self.assertEqual(self.executor.inspect(spec.identity).state, "RESERVED")

    def test_verification_only_composed_node_admission_uses_actual_central_mtls_introspection(self):
        from fastapi import FastAPI
        from unittest.mock import patch
        from sqlalchemy import delete, select
        from test_managed_nodes import ManagedNodeTests
        from hf2l_jobs.config import Settings
        from hf2l_jobs.managed_nodes import ApprovedManagedNode
        from hf2l_jobs.models import Allocation, Job, Attempt
        from hf2l_jobs.remote_node import compose_node
        from cryptography.hazmat.primitives import serialization
        ManagedNodeTests.setUpClass()
        central = ManagedNodeTests()
        central.setUp()
        self.addCleanup(central.tearDown)
        central.node_thumb = self.certificates["other"][4]
        central.manager_thumb = self.certificates["client"][4]
        central.registrations = {"node-a": ApprovedManagedNode("node-a", "cpu", central.node_thumb, "registration-a")}
        central.service = central.new_service()
        job = self._job("cpu")
        from datetime import datetime, timezone
        with central.database.transaction() as session:
            session.add(Job(id="job-composed", project_id="project-a", creator_id="human", name=job.name,
                spec_json=job.to_dict(), spec_hash=job.digest, state="PROVISIONING", target_round=1,
                epoch=1, current_attempt=1, current_round=0,
                deadline_at=datetime.fromtimestamp(central.now + 3600, timezone.utc)))
            session.flush()
            session.add(Attempt(id="attempt-composed", job_id="job-composed", number=1, epoch=1))
            session.flush()
            session.add(Allocation(id="allocation-composed", job_id="job-composed", attempt_id="attempt-composed",
                component_id="owner", pool_id="cpu", epoch=1, state="ACKNOWLEDGED", acknowledged=True,
                cpu_millicores=500, memory_bytes=128 * 1024**2, disk_bytes=32 * 1024**2,
                details_json={"node_id": "node-a", "registration_id": "registration-a"}))
        app = FastAPI()
        @app.post("/internal/jobs/v1/nodes/{job_id}/{attempt_id}/{component_id}/{epoch}/bootstrap")
        async def bootstrap(job_id: str, attempt_id: str, component_id: str, epoch: int, request: Request):
            self.assertNotIn("authorization", request.headers)
            return central.service.bootstrap(request.scope["state"]["verified_certificate_thumbprint"],
                job_id=job_id, attempt_id=attempt_id, component_id=component_id, epoch=epoch)
        @app.post("/internal/jobs/v1/nodes/{job_id}/{attempt_id}/{component_id}/{epoch}/validate")
        async def validate(job_id: str, attempt_id: str, component_id: str, epoch: int, request: Request):
            actor = central.service.authenticate_node(request.headers["authorization"],
                verified_peer_thumbprint=request.scope["state"]["verified_certificate_thumbprint"])
            return central.service.validate(actor, **await request.json())
        manager_server = start_mtls_server(app, certificate=self.certificates["server"][2],
            key=self.certificates["server"][3], client_ca=self.certificates["ca"][2])
        self.addCleanup(manager_server.server_close)
        self.addCleanup(manager_server.shutdown)
        root = self.root / "composed-node"
        root.mkdir(mode=0o700)
        catalog = root / "catalog.json"
        catalog.write_text(json.dumps({
            "sources": [{"source_id": "source-a", "projects": ["project-a"], "commits": [self.commit],
                "mirror_path": str(self.root / "approved-repository" / ".git"), "max_bytes": 1024**2,
                "max_git_bytes": 1024**2, "max_files": 64, "max_git_files": 64}],
            "runtime_images": {"runtime-a": "sha256:" + "1"*64},
        }))
        catalog.chmod(0o600)
        public_ca = root / "execution-ca.pem"
        public_ca.write_bytes(central.ca.public_bytes(serialization.Encoding.PEM))
        settings = Settings(broker=replace(central.settings, private_key=None), extra={
            "executor": {"root": str(root), "profile_path": str(root / "qualified-profile.json")},
            "node": {"node_id": "node-a", "pool_id": "cpu", "registration_id": "registration-a",
                "ledger_path": str(root / "node.sqlite"), "capacity": {
                    "cpu_millicores": 2000, "memory_bytes": 1024**3, "disk_bytes": 2*1024**3},
                "registry_file": str(catalog), "manager_endpoint": "https://127.0.0.1:" + str(manager_server.server_address[1]),
                "manager_ca_file": self.certificates["ca"][2], "identity_certificate": self.certificates["other"][2],
                "identity_key": self.certificates["other"][3], "manager_certificate_thumbprint": central.manager_thumb,
                "execution_ca_certificate": str(public_ca), "exchange_endpoint": "https://exchange.test",
                "gateway_endpoint": "https://gateway.test", "service_ca_file": self.certificates["ca"][2]}})
        runtime = RecordingRuntime(root)
        runtime.owned_root = root
        runtime.profile = {"qualified": True, "runtime": "runsc", "network": "none", "bounded_volumes": "loop-ext4"}
        runtime.qualify_health = lambda: True
        # Runtime process dispatch is already covered by the actual gVisor gate;
        # this regression exercises the full composed control/credential boundary.
        with patch("hf2l_jobs.executor.LinuxExecutor", return_value=runtime):
            service = compose_node(settings)
        self.addCleanup(service.close)
        self.assertIsNone(service.supervisor.ca_key)
        self.assertIsNone(service.supervisor.broker.settings.private_key)
        node_server = start_mtls_server(service.app, certificate=self.certificates["server"][2],
            key=self.certificates["server"][3], client_ca=self.certificates["ca"][2])
        self.addCleanup(node_server.server_close)
        self.addCleanup(node_server.shutdown)
        identity = ExecutionIdentity("job-composed", "attempt-composed", "owner", 1)
        route = NodeRoute("node-a", "cpu", ResourceLimits(500, 128*1024**2, 32*1024**2))
        endpoint = replace(self.endpoints["node-a"], origin="https://127.0.0.1:" + str(node_server.server_address[1]))
        executor = RemoteExecutor({"node-a": endpoint}, route=lambda *_: route,
            assignment_provider=lambda spec, _: RemoteAssignment(identity, "node-a", "cpu", route.resources, job,
                "sha256:" + "1"*64, source_limits={
                    "max_bytes": 1024**2, "max_git_bytes": 1024**2, "max_files": 64, "max_git_files": 64}),
            token_provider=lambda route, identity, scope: central.service.issue_control_token(identity,
                node_id=route.node_id, pool_id=route.pool_id, scope=scope,
                certificate_thumbprint=central.manager_thumb))
        self.addCleanup(executor.close)
        spec = replace(self.spec(), identity=identity, pool_id="cpu")
        self.assertTrue(executor.reserve(spec).acknowledged)
        self.assertFalse(executor.proxy_alive(identity))
        self.assertFalse((service.supervisor.root / identity.job_id).exists())
        self.assertEqual(service.agent.inventory()[0]["state"], "RESERVED")
        self.assertGreater(service.agent.inventory()[0]["auxiliary_bytes"], 0)
        assigned = service.materializer.assignment(identity)
        self.assertEqual(assigned.job_spec.digest, job.digest)
        self.assertFalse(Path(service.materializer.plan(assigned).source_path).exists())
        # A crash after node ACK but before recipe persistence still permits
        # exact-ledger inspection/cleanup, without fabricating another job path.
        (service.materializer.assignments / (identity.key + ".json")).unlink()
        self.assertEqual(executor.inspect(identity).state, "RESERVED")

    def test_node_composition_refuses_global_signing_key_and_manager_admin_sections(self):
        from hf2l_jobs.remote_node import compose_node
        from hf2l_jobs.config import Settings
        from hf2l_jobs.composition import ConfigurationError
        fields = {name: "placeholder" for name in {
            "node_id", "pool_id", "registration_id", "ledger_path", "capacity", "registry_file",
            "manager_endpoint", "manager_ca_file", "identity_certificate", "identity_key",
            "manager_certificate_thumbprint", "execution_ca_certificate", "exchange_endpoint",
            "gateway_endpoint", "service_ca_file"}}
        with self.assertRaises(ConfigurationError):
            compose_node(Settings(broker=self.broker.settings, extra={"node": fields}))
        with self.assertRaises(ConfigurationError):
            compose_node(Settings(broker=replace(self.broker.settings, private_key=None),
                extra={"node": fields, "provisioner": {"admin_token": "must-never-load"}}))

    def test_local_secret_planning_and_delivery_are_scoped_without_manager_database(self):
        from hf2l_jobs.remote_node import LocalNodeSecrets
        from hf2l_jobs.secrets import SecretError, read_secret_manifest
        directory = self.root / "operator-private-secrets"
        directory.mkdir(mode=0o700)
        path = directory / "trainer-secret"
        path.write_text("synthetic-private-value\n")
        path.chmod(0o600)
        document = self.jobs["job-a"].to_dict()
        document["secret_refs"] = {"trainer_access": "secret-own", "foreign_access": "secret-other"}
        job = JobSpec.model_validate(document)
        spec = self.spec()
        route = self.routes["job-a"]
        assignment = RemoteAssignment(spec.identity, route.node_id, route.pool_id, route.resources, job,
                                      "sha256:" + "1"*64)
        resolver = LocalNodeSecrets(self.root / "sealed-secrets", {
            "secret-own": {"project_id": "project-a", "path": str(path),
                           "roles": ["owner"], "option_names": ["trainer_access"], "component_ids": ["owner"]},
            "secret-other": {"project_id": "project-a", "path": str(directory / "must-not-be-read"),
                             "roles": ["participant"], "option_names": ["foreign_access"]}})
        planned = resolver.planned(assignment)
        self.assertIsNotNone(planned)
        self.assertFalse(planned.exists())
        resolver.materialize(assignment, {"secret_option_names": ["trainer_access"]}, planned)
        manifest = read_secret_manifest(planned, assignment.identity)
        self.assertEqual(manifest["options"], {"trainer_access": "synthetic-private-value"})
        resolver.materialize(assignment, {"secret_option_names": ["trainer_access"]}, planned)
        with self.assertRaises(SecretError):
            resolver.materialize(assignment, {"secret_option_names": ["foreign_access"]}, planned)
        with self.assertRaises(SecretError):
            resolver.materialize(assignment, {"secret_option_names": ["trainer_access"]},
                                 self.root / "another-job" / "secrets.json")
        with self.assertRaises(SecretError):
            LocalNodeSecrets(self.root / "forbidden", {"broad-key": {
                "project_id": "project-a", "path": str(path), "roles": ["owner"], "option_names": ["manager_token"]}})


    def test_purge_receipt_is_durable_typed_and_exactly_bound_to_owned_job(self):
        spec = self.spec()
        self.prepare(spec)
        self.executor.stop(spec.identity)
        self.executor.collect(spec.identity)
        self.executor.release(spec.identity)
        expected = self.jobs["job-a"].digest
        receipt = self.executor.purge_receipt(spec.identity, spec_digest=expected)
        self.assertEqual(receipt["purpose"], "managed_node_purge")
        self.assertEqual(receipt["operation_id"], "purge-" + spec.identity.key)
        for name in ("source_deleted", "config_deleted", "build_deleted", "private_credentials_deleted",
                     "private_secrets_deleted", "retained_deleted", "auxiliary_deleted", "termination_confirmed"):
            self.assertIs(receipt[name], True)
        materializer = self.nodes["node-a"][1]
        durable = materializer.purge_receipts / (spec.identity.key + ".json")
        self.assertEqual(json.loads(durable.read_bytes()), receipt)
        self.assertEqual(self.executor.purge_receipt(spec.identity, spec_digest=expected), receipt)
        with self.assertRaises(ExecutorRefused):
            self.executor.purge_receipt(spec.identity, spec_digest="1"*64)

    def test_source_approval_intersection_constrains_actual_node_materialization(self):
        from hf2l_jobs.source import SourceError
        materializer = self.nodes["node-a"][1]
        spec, route = self.spec(), self.routes["job-a"]
        bounds = {"max_bytes": 1, "max_git_bytes": 1024**2, "max_files": 32, "max_git_files": 64}
        assignment = RemoteAssignment(spec.identity, route.node_id, route.pool_id, route.resources,
            self.jobs["job-a"], "sha256:" + "1"*64, source_limits=bounds)
        effective = materializer._registry(assignment).source_registry.approvals["source-a"]
        self.assertEqual(effective.max_bytes, 1)
        self.assertEqual(effective.max_files, 32)
        self.assertNotEqual(materializer.registry.source_registry.approvals["source-a"].max_bytes, 1)
        materializer.reserve(assignment)
        with self.assertRaises(SourceError):
            materializer.prepare(spec.identity, self.configuration(spec))
        self.assertFalse(Path(materializer.plan(assignment).source_path).exists())
        with self.assertRaises(ExecutorRefused):
            replace(assignment, source_limits={**bounds, "mirror_path": "/another-user/code"})

    def test_remote_canonical_logs_are_bounded_and_retained_until_owned_purge(self):
        spec = self.spec()
        self.prepare(spec)
        runtime = self.nodes["node-a"][2]
        content = b"scoped node log [REDACTED]\n"
        def read_logs(identity, offset=0, max_bytes=65536):
            part = content[offset:offset+max_bytes]
            return {"identity": asdict(identity), "source_id": identity.key, "offset": offset,
                    "next_offset": offset + len(part), "content": part.decode(),
                    "complete": runtime.inspect(identity).termination_confirmed, "truncated": False}
        runtime.read_logs = read_logs
        first = self.executor.read_logs(spec.identity, max_bytes=8)
        self.assertEqual(first["content"], content[:8].decode())
        self.assertEqual(first["next_offset"], 8)
        self.assertEqual(self.executor.read_logs(spec.identity, 8)["content"], content[8:].decode())
        with self.assertRaises(ExecutorRefused):
            self.executor.read_logs(spec.identity, max_bytes=1)
        self.executor.stop(spec.identity)
        self.executor.collect(spec.identity)
        self.executor.release(spec.identity)
        terminal = self.executor.read_logs(spec.identity)
        self.assertTrue(terminal["complete"])
        self.assertEqual(terminal["source_id"], spec.identity.key)
        self.executor.purge(spec.identity)
        with self.assertRaises(ExecutorRefused):
            self.executor.read_logs(spec.identity)

    def test_omitted_or_false_purge_wire_proof_cannot_release_storage(self):
        from hf2l_jobs.remote_node import NodePurgeReceipt
        spec = self.spec()
        good = NodePurgeReceipt(**asdict(spec.identity), node_id="node-a", pool_id="pool-a",
            spec_digest=self.jobs["job-a"].digest, operation_id="purge-" + spec.identity.key).as_dict()
        for field in ("auxiliary_deleted", "source_deleted", "private_credentials_deleted", "termination_confirmed"):
            for change in ("omitted", False):
                bad = dict(good)
                if change == "omitted":
                    del bad[field]
                else:
                    bad[field] = False
                executor = self._executor(client_factory=lambda endpoint: httpx.Client(
                    transport=httpx.MockTransport(lambda request: httpx.Response(200, json=bad)), trust_env=False))
                try:
                    with self.subTest(field=field, change=change), self.assertRaises(UncertainExecution):
                        executor.purge_receipt(spec.identity)
                finally:
                    executor.close()


if __name__ == "__main__":
    unittest.main()
