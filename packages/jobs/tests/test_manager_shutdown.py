"""Actual manager shutdown preserves durable jobs and authenticated sessions.

The HTTPS process keeps a real dashboard SSE connection open while SIGTERM is
handled. This qualifies control-plane lifecycle behavior, not training isolation.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import secrets
import signal
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.parse import urlsplit

import httpx

from support_system import TLSOIDCProvider, free_port


def serve_fixture(configuration_path):
    """Serve the actual API through the production Uvicorn composition."""
    from hf2l_jobs.api import create_app
    from hf2l_jobs.application import Manager
    from hf2l_jobs.auth import AuthService
    from hf2l_jobs.composition import _uvicorn
    from hf2l_jobs.config import OIDCSettings, Settings
    from hf2l_jobs.database import create_database
    from hf2l_jobs.oidc import OIDCProvider

    configuration = json.loads(Path(configuration_path).read_text())
    settings = Settings(
        database_url=configuration["database_url"],
        cursor_secret=configuration["cursor_secret"],
        session_secret=configuration["session_secret"],
        graceful_shutdown_timeout_seconds=1,
        oidc=OIDCSettings(
            issuer=configuration["issuer"], client_id="integration-client",
            redirect_uri=configuration["base_url"] + "/auth/callback",
            audience="hf2l-jobs",
        ),
        extra={"service": {
            "host": "127.0.0.1", "port": configuration["port"],
            "tls_certificate": configuration["certificate"],
            "tls_key": configuration["private_key"],
        }},
    ).validate()
    database = create_database(settings.database_url, initialize=False)
    context = ssl.create_default_context(cafile=configuration["certificate"])
    with httpx.Client(verify=context, trust_env=False) as identity_client:
        try:
            auth = AuthService(database.session_factory, settings,
                               oidc_provider=OIDCProvider(settings.oidc, identity_client))
            manager = Manager(database, cursor_secret=settings.cursor_secret)
            app = create_app(manager, auth, cursor_secret=settings.cursor_secret,
                             allow_local_http=False, sse_poll_seconds=.05)
            _uvicorn(app, settings, argparse.Namespace(host=None, port=None))
        finally:
            database.close()


class ManagerGracefulShutdownTests(unittest.TestCase):
    def test_sigterm_with_open_dashboard_stream_preserves_job_and_session(self):
        from hf2l_jobs.auth import principal_id
        from hf2l_jobs.database import create_database
        from hf2l_jobs import models
        from sqlalchemy import select

        with ExitStack() as stack:
            directory = Path(stack.enter_context(
                tempfile.TemporaryDirectory(prefix="manager-shutdown-")))
            identity = TLSOIDCProvider(directory)
            stack.callback(identity.close)
            database_url = "sqlite:///" + str(directory / "manager.db")
            database = create_database(database_url)
            stack.callback(database.close)
            owner_id = principal_id(identity.issuer, "alice")
            commit, image = "a" * 40, "sha256:" + "b" * 64
            with database.transaction() as session:
                session.add(models.Project(id="project", name="Shutdown regression"))
                session.flush()
                session.add_all([
                    models.ProjectMember(project_id="project", principal_id=owner_id,
                                         role="submitter"),
                    models.ApprovedSource(
                        id="source", project_id="project", name="Exact synthetic commit",
                        url="https://example.invalid/project.git", allowed_commits=[commit],
                        allowed_hosts=["example.invalid"]),
                    models.RuntimeImage(id="runtime", project_id="project", digest=image),
                    models.Pool(id="pool", name="Synthetic control-plane pool", node_id="node",
                                cpu_millicores=3000, memory_bytes=2**30, disk_bytes=2**30,
                                healthy=False, sandbox_profiles=["runsc-cpu-v1"]),
                    *[models.ParticipantBinding(
                        id="dataset-" + subject, project_id="project", participant_id=subject,
                        node_id="node", dataset_label="Synthetic " + subject)
                      for subject in ("alice", "bob")],
                ])
            port = free_port()
            base_url = "https://127.0.0.1:" + str(port)
            configuration = {
                "database_url": database_url, "port": port, "base_url": base_url,
                "issuer": identity.issuer, "certificate": str(identity.cert_path),
                "private_key": str(identity.tls_key_path),
                "cursor_secret": secrets.token_urlsafe(32),
                "session_secret": secrets.token_urlsafe(32),
            }
            configuration_path = directory / "fixture.json"
            configuration_path.write_text(json.dumps(configuration))
            configuration_path.chmod(0o600)
            client = stack.enter_context(httpx.Client(
                base_url=base_url, verify=identity.context, trust_env=False,
                follow_redirects=False, timeout=5))
            processes, log_paths, shutdown_evidence = [], [], []
            evidence_directory = os.environ.get("HF2L_SHUTDOWN_TEST_EVIDENCE_DIR")
            log_directory = Path(evidence_directory) if evidence_directory else directory
            log_directory.mkdir(mode=0o700, parents=True, exist_ok=True)

            def cleanup_processes():
                for process in processes:
                    if process.poll() is None:
                        # A hung process is always a test failure. Kill only in
                        # cleanup so a failing regression cannot leak a server.
                        process.kill()
                        process.wait(timeout=5)
            stack.callback(cleanup_processes)

            def start_manager():
                log_path = log_directory / ("manager-" + str(len(processes)) + ".log")
                log_file = stack.enter_context(log_path.open("wb"))
                environment = dict(os.environ)
                environment.update(OMP_NUM_THREADS="2", MKL_NUM_THREADS="2",
                                   OPENBLAS_NUM_THREADS="2")
                process = subprocess.Popen(
                    [sys.executable, str(Path(__file__).resolve()),
                     "--serve-fixture", str(configuration_path)],
                    stdout=log_file, stderr=subprocess.STDOUT, env=environment,
                )
                processes.append(process)
                log_paths.append(log_path)
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        self.fail("Manager startup failed: " + log_path.read_text())
                    try:
                        response = client.get("/healthz", timeout=.5)
                        if response.status_code == 200:
                            return process
                    except httpx.TransportError:
                        pass
                    time.sleep(.05)
                self.fail("Manager startup timed out: " + log_path.read_text())

            def login():
                begin = client.get("/auth/login")
                self.assertEqual(begin.status_code, 303)
                callback = urlsplit(identity.authorize(begin.headers["location"]))
                response = client.get(callback.path + "?" + callback.query)
                self.assertEqual(response.status_code, 303)
                response = client.get("/api/jobs/v1/session")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["principal"]["principal_id"], owner_id)
                return response.json()

            def stop_manager(process, *, active_stream=False):
                started = time.monotonic()
                process.send_signal(signal.SIGTERM)
                try:
                    status = process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    self.fail("SIGTERM did not stop the manager within eight seconds "
                              "while the dashboard stream remained open")
                # Current Uvicorn re-raises the captured termination signal after
                # its lifespan completes; this is an orderly SIGTERM outcome.
                self.assertIn(status, (0, -signal.SIGTERM), log_paths[-1].read_text())
                elapsed = time.monotonic() - started
                self.assertLess(elapsed, 8)
                shutdown_evidence.append({"return_code": status, "elapsed_seconds": elapsed})
                self.assertIn("Finished server process", log_paths[-1].read_text())
                if active_stream:
                    self.assertIn("timeout graceful shutdown exceeded", log_paths[-1].read_text())
                self.assertIn("Application shutdown complete", log_paths[-1].read_text())
                self.assertNotIn("Traceback", log_paths[-1].read_text().split(
                    "Application shutdown complete")[-1])

            process = start_manager()
            authentication = login()
            spec = {
                "project_id": "project", "name": "Durable shutdown job",
                "source_id": "source", "source_commit": commit,
                "runtime_image": "runtime", "plugin": "examples.lenet:Plugin",
                "options": {"seed": 7},
                "participants": [
                    {"participant_id": subject, "component_id": "client-" + subject,
                     "mode": "managed", "dataset_binding": "dataset-" + subject}
                    for subject in ("alice", "bob")],
                "components": [
                    {"component_id": "owner", "role": "owner", "resources": {
                        "pool_id": "pool", "cpu_millicores": 1000,
                        "memory_bytes": 64 * 1024**2, "disk_bytes": 64 * 1024**2}},
                    *[{"component_id": "client-" + subject, "role": "participant",
                       "participant_id": subject, "resources": {
                           "pool_id": "pool", "cpu_millicores": 250,
                           "memory_bytes": 64 * 1024**2, "disk_bytes": 64 * 1024**2}}
                      for subject in ("alice", "bob")]],
                "target_round": 2, "max_duration_seconds": 300,
            }
            created = client.post("/api/jobs/v1/jobs", json=spec, headers={
                "Idempotency-Key": "shutdown-job", "Origin": base_url,
                "X-CSRF-Token": authentication["csrf_token"],
            })
            self.assertEqual(created.status_code, 202, created.text)
            job_id = created.json()["id"]
            with database.transaction(immediate=False) as session:
                original_session_ids = set(session.scalars(select(models.AuthSession.id)))
            self.assertEqual(len(original_session_ids), 1)
            original_cookie = client.cookies.get("__Host-hf2l_jobs")

            # Reading the first event proves this is an active, authenticated
            # response. Leave the response context open throughout SIGTERM.
            with client.stream("GET", "/api/jobs/v1/events/stream", timeout=5) as stream:
                self.assertEqual(stream.status_code, 200)
                self.assertIn("text/event-stream", stream.headers["content-type"])
                lines = stream.iter_lines()
                self.assertTrue(next(lines).startswith("event: "))
                stop_manager(process, active_stream=True)

            with database.transaction(immediate=False) as session:
                self.assertEqual(
                    set(session.scalars(select(models.AuthSession.id))),
                    original_session_ids)
                self.assertEqual(session.get(models.Job, job_id).name, "Durable shutdown job")
            process = start_manager()
            self.assertEqual(client.cookies.get("__Host-hf2l_jobs"), original_cookie)
            restored_session = client.get("/api/jobs/v1/session")
            self.assertEqual(restored_session.status_code, 200)
            self.assertEqual(restored_session.json()["principal"]["principal_id"], owner_id)
            self.assertEqual(restored_session.json()["csrf_token"], authentication["csrf_token"])
            restored_job = client.get("/api/jobs/v1/jobs/" + job_id)
            self.assertEqual(restored_job.status_code, 200)
            self.assertEqual(restored_job.json()["id"], job_id)
            self.assertEqual(restored_job.json()["state"], created.json()["state"])
            self.assertEqual(restored_job.json()["version"], created.json()["version"])
            self.assertEqual(login()["principal"]["principal_id"], owner_id)
            stop_manager(process)
            self.assertIn(("POST", "/token"), identity.requests)
            self.assertIn(("GET", "/jwks"), identity.requests)
            receipt = {"test": "manager_sigterm_open_sse", "shutdowns": shutdown_evidence,
                       "durable_job_preserved": True, "original_session_preserved": True,
                       "fresh_login_after_restart": True}
            if evidence_directory:
                (log_directory / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
            print(json.dumps(receipt), flush=True)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--serve-fixture":
        serve_fixture(sys.argv[2])
    else:
        unittest.main()
