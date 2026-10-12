"""Opt-in real gVisor/Exchange publication-failure acceptance driver.

Uses task-owned PostgreSQL schema, versioned S3 bucket, real mTLS gateway and
per-execution UDS proxies. It never substitutes LocalStore or a host trainer for
the qualified worker. Run with the retained live_services helper on PYTHONPATH.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import ssl
import sys
import threading
import time
import uuid

import httpx
import uvicorn

from hf2l.backends.exchange import ExchangeStore
from hf2l_exchange.client import ExchangeClient
from hf2l_jobs.broker import stable_workload_principal, stable_workload_subject
from hf2l_jobs.execution_proxy import ExecutionBinding, ProxySettings, create_proxy_app
from hf2l_jobs.executor import ExecutionIdentity, ExecutionSpec, LinuxExecutor, ResourceLimits
from hf2l_jobs.workflow import RuntimeConfig
from managed_training_validation import job_spec, write_source_repository


class LostAcknowledgment:
    """Lose only the client-side acknowledgment of a real initial main update."""
    def __init__(self, app, space_id, *, accept):
        self.app, self.space_id, self.accept = app, space_id, accept
        self.attempts, self.accepted = 0, 0

    async def __call__(self, scope, receive, send):
        matched = scope["type"] == "http" and scope["method"] == "PUT" and (
            scope["path"] == "/v2/spaces/" + self.space_id + "/refs/main")
        if not matched:
            return await self.app(scope, receive, send)
        self.attempts += 1
        if self.accept:
            messages = []
            async def capture(message):
                messages.append(message)
            await self.app(scope, receive, capture)
            status = next(message["status"] for message in messages if message["type"] == "http.response.start")
            if status >= 300:
                for message in messages:
                    await send(message)
                return
            self.accepted += 1
        body = b'{"error":{"code":"synthetic_acknowledgment_lost"}}'
        await send({"type": "http.response.start", "status": 503,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


@contextmanager
def execution_proxy(settings, path, *, fault=None):
    app = create_proxy_app(settings)
    wrapped = LostAcknowledgment(app, settings.binding.space_id, accept=fault == "accepted") if fault else app
    path = Path(path)
    server = uvicorn.Server(uvicorn.Config(wrapped, uds=str(path), log_level="error",
                                           access_log=False, proxy_headers=False, lifespan="on"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    until = time.monotonic() + 10
    while not server.started:
        if not thread.is_alive() or time.monotonic() > until:
            raise RuntimeError("The isolated execution proxy did not start")
        time.sleep(.025)
    os.chmod(path, 0o666)
    try:
        yield wrapped
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        if thread.is_alive():
            server.force_exit = True
            thread.join(timeout=5)
        path.unlink(missing_ok=True)


class ManagedFailureDriver:
    def __init__(self, live, profile, image, root):
        self.live, self.image = live, image
        self.root = Path(root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.executor = LinuxExecutor(profile_path=profile, root=self.root / "executor")
        self.active = []
        self.jobs = {}
        self.report = {"qualified_runtime": True, "training_transport": "execution-uds/mTLS/Exchange/PostgreSQL/S3",
                       "publication_failures": {}, "security_checks": [], "cleanup_confirmed": False}

    def job(self, name, seed):
        directory = self.root / name
        directory.mkdir(mode=0o700)
        foreign = self.root / ("job-b" if name == "job-a" else "job-a") / "source" / "job-marker.txt"
        source = write_source_repository(directory / "source", name, foreign)
        spec = job_spec(name, source["commit"], "approved-cpu", "cpu", target_round=1, seed=seed)
        space = self.live.admin.create_space(name, profile="fedavg.v1")
        self.live.admin.manage_space(space.id, job_id=name)
        schemas = {
            "model.global": {"type": "object", "properties": {"hf2l_files": {"type": "object"},
                "inputs": {"type": "array"}, "base_record_id": {"type": "string"}},
                "required": ["hf2l_files", "inputs"]},
            "training.update": {"type": "object", "properties": {"hf2l_files": {"type": "object"},
                "sample_count": {"type": "integer"}, "base_record_id": {"type": "string"}},
                "required": ["hf2l_files", "sample_count", "base_record_id"]},
        }
        for kind, schema in schemas.items():
            self.live.admin.register_type(space.id, kind, schema)
        principal = stable_workload_principal(self.live.workload_issuer, name, "owner")
        subject = stable_workload_subject(name, "owner")
        self.live.admin.set_member(space.id, principal, ["reader", "contributor", "publisher"], subject=subject)
        state = directory / "state"
        state.mkdir(mode=0o700)
        job = {"id": name, "directory": directory, "source": source, "spec": spec,
               "space": space.id, "principal": principal, "subject": subject, "state": state}
        self.jobs[name] = job
        return job

    def credentials(self, job, attempt, epoch):
        certificate = self.live.mint_execution_certificate(job["id"] + "-" + attempt)
        grant = self.live.admin.create_workload_grant(job["space"], subject=job["subject"],
            job_id=job["id"], attempt_id=attempt, component_id="owner", epoch=epoch,
            expires_at=time.time() + 900, certificate_thumbprint=certificate.thumbprint,
            roles=["reader", "contributor", "publisher"])
        values = {"job_id": job["id"], "attempt_id": attempt, "component_id": "owner",
                  "space_id": job["space"], "grant_id": grant.grant_id, "epoch": epoch,
                  "certificate_thumbprint": certificate.thumbprint}
        settings = ProxySettings(
            exchange_endpoint=self.live.private_endpoint, gateway_endpoint=self.live.gateway_endpoint,
            client_certificate=certificate.certificate, client_key=certificate.private_key,
            ca_file=self.live.ca_file,
            binding=ExecutionBinding(job["id"], attempt, "owner", job["space"], epoch, certificate.thumbprint),
            exchange_token=lambda: self.live.broker.issue_workload(**values, audience="exchange"),
            gateway_token=lambda: self.live.broker.issue_workload(**values, audience="gateway"),
            workload_issuer=self.live.workload_issuer, workload_public_key=self.live.workload_public_key)
        return settings, values, certificate

    def worker(self, job, attempt, epoch, socket_path):
        directory = job["directory"] / attempt
        directory.mkdir(mode=0o700)
        config = RuntimeConfig.model_validate({
            "role": "init", "job_id": job["id"], "attempt_id": attempt, "component_id": "owner",
            "space_id": job["space"], "epoch": epoch, "spec": job["spec"].to_dict(),
            "spec_digest": job["spec"].digest, "source_manifest": job["source"]["manifest"],
            "participant_principals": {participant: stable_workload_principal(
                self.live.workload_issuer, job["id"], "client-" + participant, participant)
                for participant in ("alice", "bob")},
            "source_dir": "/job/source", "state_dir": "/job/state", "poll_interval": .1})
        config_path = directory / "runtime.json"
        config_path.write_text(json.dumps(config.to_dict(), sort_keys=True), encoding="utf-8")
        config_path.chmod(0o600)
        identity = ExecutionIdentity(job["id"], attempt, "owner", epoch)
        spec = ExecutionSpec(identity=identity, image_digest=self.image,
            source_path=job["source"]["root"], state_path=str(job["state"]),
            argv=("python", "-m", "hf2l_jobs.runtime", "--config", "/run/hf2l/runtime.json"),
            proxy_endpoint=str(socket_path), resources=ResourceLimits(500, 768 * 1024 ** 2, 64 * 1024 ** 2),
            config_path=str(config_path), pool_id="cpu", node_id="validation-node",
            deadline=time.time() + 240, lease_seconds=240)
        self.executor.reserve(spec)
        self.active.append(identity)
        self.executor.start(identity)
        until = time.monotonic() + 180
        while True:
            observation = self.executor.inspect(identity)
            if observation.termination_confirmed:
                break
            if time.monotonic() > until:
                self.executor.stop(identity, grace_seconds=2)
                raise TimeoutError("Managed initialization exceeded its bounded validation deadline")
            time.sleep(.2)
        captured = self.executor._docker(["logs", "hf2l-" + identity.key], allow_failure=True)
        (directory / "worker.log").write_text(captured.stdout + captured.stderr, encoding="utf-8")
        self.executor.collect(identity)
        assert self.executor.release(identity)
        self.active.remove(identity)
        isolation = json.loads((job["state"] / "isolation.json").read_text())
        assert isolation["job_marker"] == job["id"]
        assert all(isolation[key] is True for key in (
            "foreign_resources_denied", "source_read_only", "upstream_credentials_absent",
            "direct_storage_network_denied", "assigned_proxy_present"))
        return observation.exit_code

    def run(self):
        a, b = self.job("job-a", 7), self.job("job-b", 9)
        settings_a, tokens_a, cert_a = self.credentials(a, "a1", 1)
        settings_b, tokens_b, cert_b = self.credentials(b, "b1", 1)
        socket_a, socket_b = a["directory"] / "p1.sock", b["directory"] / "p1.sock"
        with execution_proxy(settings_a, socket_a, fault="accepted") as fault_a:
            assert self.worker(a, "a1", 1, socket_a) == 4
            before = self.live.admin.resolve(a["space"], "main")
            initial = self.live.admin.get_record(a["space"], before.record_id)
            assert initial.state == "published"
            assert len(list(self.live.admin.records(a["space"], kind="model.global", state="published"))) == 1
            state = json.loads((a["state"] / "initialization.json").read_text())
            assert state["phase"] == "uncertain"
            assert fault_a.accepted > 0
            self.report["publication_failures"]["accepted_then_ack_lost"] = {
                "exit_code": 4, "needs_attention": True, "published_initial_models": 1,
                "proxy_attempts": fault_a.attempts, "main": before.record_id}
            with execution_proxy(settings_b, socket_b, fault="unknown") as fault_b:
                assert self.worker(b, "b1", 1, socket_b) == 4
                attempts = fault_b.attempts
                self.live.admin.revoke_workload_grants(b["space"], attempt_id="b1")
                settings_b2, _, _ = self.credentials(b, "b2", 2)
                socket_b2 = b["directory"] / "p2.sock"
                with execution_proxy(settings_b2, socket_b2, fault="unknown") as fault_b2:
                    assert self.worker(b, "b2", 2, socket_b2) == 4
                    assert fault_b2.attempts == 0
                assert fault_b.attempts == attempts
                unknown = json.loads((b["state"] / "initialization.json").read_text())
                assert unknown["phase"] == "uncertain"
                try:
                    self.live.admin.resolve(b["space"], "main")
                except Exception as exc:
                    assert getattr(exc, "status", None) == 404
                else:
                    raise AssertionError("The rejected publication gained a main reference")
                self.report["publication_failures"]["unknown_not_replayed"] = {
                    "exit_codes": [4, 4], "needs_attention": True, "main_absent": True,
                    "proxy_attempts_unchanged_on_retry": True, "proxy_attempts": attempts}
                transport = httpx.HTTPTransport(uds=str(socket_b))
                with httpx.Client(transport=transport, base_url="http://proxy", trust_env=False) as client:
                    assert client.get("/v2/spaces/" + a["space"] + "/records").status_code == 404
                    assert client.get("/v2/spaces/" + b["space"] + "/records",
                                      headers={"Authorization": "Bearer copied-human-token"}).status_code == 400
                context = ssl.create_default_context(cafile=self.live.ca_file)
                context.load_cert_chain(cert_a.certificate, cert_a.private_key)
                with httpx.Client(verify=context, trust_env=False, timeout=5) as client:
                    stolen = self.live.broker.issue_workload(**tokens_b, audience="exchange")
                    response = client.get(self.live.private_endpoint + "/v2/spaces/" + b["space"] + "/records",
                                          headers={"Authorization": "Bearer " + stolen})
                    assert response.status_code == 401
                    own = self.live.broker.issue_workload(**tokens_a, audience="exchange")
                    response = client.get(self.live.private_endpoint + "/v2/spaces/" + b["space"] + "/records",
                                          headers={"Authorization": "Bearer " + own})
                    assert response.status_code in (403, 404)
                self.report["security_checks"].extend([
                    "cross-job control path denied at execution UDS", "caller credentials denied at execution UDS",
                    "copied job JWT denied with another execution certificate",
                    "own certificate-bound token denied at another job space"])
        self.live.admin.revoke_workload_grants(a["space"], attempt_id="a1")
        settings_a2, _, _ = self.credentials(a, "a2", 2)
        socket_a2 = a["directory"] / "p2.sock"
        with execution_proxy(settings_a2, socket_a2):
            assert self.worker(a, "a2", 2, socket_a2) == 0
            after = self.live.admin.resolve(a["space"], "main")
            assert after == before
            assert len(list(self.live.admin.records(a["space"], kind="model.global", state="published"))) == 1
            state = json.loads((a["state"] / "initialization.json").read_text())
            assert state["phase"] == "published" and state["reconciled"] is True
            with ExchangeClient.for_execution(str(socket_a2), space=a["space"]) as client:
                store = ExchangeStore(None, "http://proxy", client=client)
                snapshot = self.root / "downloaded-initial"
                store.download_snapshot(a["space"], after.record_id, snapshot)
                advertised = initial.metadata["hf2l_files"]["fedavg_round.json"]["checkpoint_files_sha256"]
                for filename, digest in advertised.items():
                    assert hashlib.sha256((snapshot / filename).read_bytes()).hexdigest() == digest
                store.close()
            self.report["publication_failures"]["accepted_then_ack_lost"].update(
                reconciled_exit_code=0, no_reinitialization=True, main_unchanged=True,
                reconciled_actual_blob_hashes=True)
        saved_attempts = {}
        for job, attempts in ((a, (("a1", 1), ("a2", 2))), (b, (("b1", 1), ("b2", 2)))):
            values = []
            for attempt, epoch in attempts:
                identity = ExecutionIdentity(job["id"], attempt, "owner", epoch)
                retained = self.executor._directory(identity) / "retained" / "state"
                intent = json.loads((retained / "initialization.json").read_text())
                manifest_hash = hashlib.sha256((retained / "initial-model" / "fedavg_round.json").read_bytes()).hexdigest()
                assert manifest_hash == intent["manifest_sha256"]
                for filename, digest in intent["checkpoint_files_sha256"].items():
                    assert hashlib.sha256((retained / "initial-model" / filename).read_bytes()).hexdigest() == digest
                values.append(intent)
            assert values[0]["manifest_sha256"] == values[1]["manifest_sha256"]
            assert values[0]["checkpoint_files_sha256"] == values[1]["checkpoint_files_sha256"]
            saved_attempts[job["id"]] = {
                "manifest_sha256": values[0]["manifest_sha256"],
                "checkpoint_files_sha256": values[0]["checkpoint_files_sha256"],
                "saved_phases": [value["phase"] for value in values],
                "saved_initial_bytes_unchanged": True}
        self.report["retained_initialization_proof"] = saved_attempts
        self.live.admin.revoke_workload_grants(a["space"], attempt_id="a1")
        self.live.admin.revoke_workload_grants(a["space"], attempt_id="a2")
        self.live.admin.revoke_workload_grants(b["space"], attempt_id="b1")
        self.live.admin.revoke_workload_grants(b["space"], attempt_id="b2")
        self.report["security_checks"].append("sandbox source/credentials/network isolation confirmed by real plugin")
        self.report["cleanup_confirmed"] = True
        return self.report

    def close(self):
        errors = []
        for identity in tuple(self.active):
            try:
                observed = self.executor.stop(identity, grace_seconds=2)
                if observed.termination_confirmed:
                    self.executor.release(identity)
                    self.active.remove(identity)
            except Exception as exc:
                errors.append(type(exc).__name__)
        if errors:
            self.report["cleanup_confirmed"] = False
            self.report["cleanup_errors"] = errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--image", required=True)
    parser.add_argument("--services-tools", required=True, type=Path)
    parser.add_argument("--artifacts", required=True, type=Path)
    args = parser.parse_args(argv)
    sys.path.insert(0, str(args.services_tools))
    from live_services import LiveServices
    profile = json.loads(args.profile.read_text())
    root = Path(profile["owned_root"]) / ("f-" + uuid.uuid4().hex[:6])
    args.artifacts.mkdir(mode=0o700, parents=True, exist_ok=True)
    result = {"status": "running", "root": str(root), "profile": str(args.profile), "runtime_image": args.image}
    driver = None
    try:
        with LiveServices(args.artifacts / ("services-" + uuid.uuid4().hex[:8])) as live:
            driver = ManagedFailureDriver(live, args.profile, args.image, root)
            try:
                result.update(driver.run())
                result["status"] = "passed"
            finally:
                driver.close()
                result.update(driver.report)
    except Exception as exc:
        result.update(status="failed", error_type=type(exc).__name__, error=str(exc))
        raise
    finally:
        (args.artifacts / "managed-publication-failures.json").write_text(
            json.dumps(result, sort_keys=True, indent=2), encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
