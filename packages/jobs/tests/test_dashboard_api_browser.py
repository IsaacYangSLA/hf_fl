"""Browser acceptance against real Manager/SQL/FastAPI with test-only identity.

Run with the jobs server extra and Playwright installed. No training code is
executed; this gate checks dashboard/API persistence, ACLs, CSRF, SSE, logs,
artifact brokerage and lifecycle controls.
"""
from __future__ import annotations
import asyncio
from contextlib import asynccontextmanager
from datetime import timedelta
import ipaddress
import os
from pathlib import Path
import socket
import tempfile
import threading
from types import SimpleNamespace
import unittest

try:
    from playwright.async_api import async_playwright
    import uvicorn
    from hf2l_jobs.api import create_app
    from hf2l_jobs.application import Manager
    from hf2l_jobs.database import create_database
    from hf2l_jobs.domain import Error, utcnow
    from hf2l_jobs import models
    AVAILABLE = True
except ImportError:
    if os.environ.get("JOBS_REQUIRE_BROWSER_TESTS") == "1":
        raise
    AVAILABLE = False


class BrowserIdentity:
    """Synthetic session boundary only; Manager still checks real memberships."""
    def __init__(self, origin):
        self.origin = origin
        self.revoked = False

    def authenticate_request(self, authorization="", session_token="", touch=True):
        if self.revoked or session_token != "alice":
            raise Error(401, "session_expired")
        return SimpleNamespace(id="alice", display_name="Alice research", platform_operator=False)

    def session_info(self, token):
        actor = self.authenticate_request(session_token=token)
        return {"authenticated": True, "principal": {"principal_id": actor.id, "display_name": actor.display_name},
                "permissions": [], "csrf_token": "test-csrf-alice", "login_url": "/auth/login"}

    def require_csrf(self, token, csrf, origin=""):
        if token != "alice" or csrf != "test-csrf-alice" or origin != self.origin:
            raise Error(403, "csrf_required")

    def logout(self, token, csrf, origin=""):
        self.require_csrf(token, csrf, origin)
        self.revoked = True


class BrowserArtifactBroker:
    """An authorized synthetic byte stream, independent of private origin I/O."""
    def __init__(self, manager):
        self.manager = manager

    @asynccontextmanager
    async def open_authorized(self, principal, job_id, artifact_id):
        self.manager.artifact_storage(principal, job_id, artifact_id)
        payload = b"synthetic-checkpoint-bytes"
        async def chunks():
            yield payload
        yield SimpleNamespace(name="global-checkpoint.bin", size=len(payload), chunks=chunks())


@unittest.skipUnless(AVAILABLE, "Playwright and jobs server dependencies required")
class DashboardAPIBrowserTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = create_database("sqlite:///" + str(Path(self.temp.name) / "manager.sqlite"))
        self.manager = Manager(self.db, "s"*32)
        with self.db.transaction() as session:
            session.add(models.Project(id="research", name="Research", quotas_json={"cpu_millicores": 8000, "memory_bytes": 16 << 30, "disk_bytes": 32 << 30}))
            session.flush()
            for principal in ("alice", "bob"):
                session.add(models.ProjectMember(project_id="research", principal_id=principal, role="submitter"))
            session.add(models.ApprovedSource(id="approved", project_id="research", name="Approved code", url="https://github.com/example/project.git", allowed_hosts=["github.com"], allowed_commits=["a"*40], enabled=True))
            session.add(models.RuntimeImage(id="cpu-image", name="CPU runtime", digest="sha256:"+"b"*64, enabled=True, approved=True))
            session.add(models.Pool(id="cpu", name="CPU lab", node_id="node-a", cpu_millicores=8000, memory_bytes=16 << 30, disk_bytes=32 << 30, sandbox_profiles=["runsc-cpu-v1"], healthy=True, quarantined=False))
            for suffix in ("a", "b"):
                session.add(models.DatasetBinding(id="data-" + suffix, project_id="research",
                    participant_id="participant-" + suffix, node_id="node-a",
                    dataset_label="Approved participant " + suffix, enabled=True))
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.origin = "https://127.0.0.1:" + str(self.socket.getsockname()[1])
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "HF2L browser fixture")])
        certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(utcnow()-timedelta(minutes=1)).not_valid_after(utcnow()+timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))
        key_path, cert_path = Path(self.temp.name)/"fixture.key", Path(self.temp.name)/"fixture.crt"
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        self.auth = BrowserIdentity(self.origin)
        self.app = create_app(self.manager, self.auth, cursor_secret="s"*32, allow_local_http=False, artifact_broker=BrowserArtifactBroker(self.manager), sse_poll_seconds=.1)
        self.server = uvicorn.Server(uvicorn.Config(self.app, log_level="error", lifespan="off", timeout_graceful_shutdown=1, ssl_keyfile=str(key_path), ssl_certfile=str(cert_path)))
        self.thread = threading.Thread(target=lambda: self.server.run(sockets=[self.socket]), daemon=True)
        self.thread.start()
        for _ in range(100):
            if self.server.started:
                break
            await asyncio.sleep(.02)
        self.assertTrue(self.server.started)
        resources = {"pool_id": "cpu", "cpu_millicores": 1000, "memory_bytes": 1 << 30, "disk_bytes": 1 << 30}
        foreign = {"project_id": "research", "name": "Bob private experiment",
            "source_id": "approved", "source_commit": "a"*40, "runtime_image": "cpu-image",
            "plugin": "examples.lenet", "target_round": 2, "max_duration_seconds": 3600,
            "participants": [{"participant_id": "participant-" + suffix,
                "dataset_binding": "data-" + suffix, "mode": "managed",
                "component_id": "participant-" + suffix} for suffix in ("a", "b")],
            "components": [{"component_id": "owner", "role": "owner", "resources": resources}] +
                [{"component_id": "participant-" + suffix, "role": "participant",
                  "participant_id": "participant-" + suffix, "resources": resources}
                 for suffix in ("a", "b")]}
        self.foreign = self.manager.create_job("bob", foreign, "bob-private-create")
        self.pw = await async_playwright().start()
        self.browser = await self.pw.chromium.launch(args=["--disable-dev-shm-usage", "--ignore-certificate-errors"])
        self.context = await self.browser.new_context(viewport={"width": 1440, "height": 1000}, accept_downloads=True, ignore_https_errors=True)
        await self.context.add_cookies([{"name": "__Host-hf2l_jobs", "value": "alice", "url": self.origin + "/", "secure": True, "httpOnly": True, "sameSite": "Lax"}])
        self.page = await self.context.new_page()
        self.page.set_default_timeout(12000)
        self.errors = []
        self.page.on("pageerror", lambda err: self.errors.append(str(err)))

    async def asyncTearDown(self):
        self.assertEqual(self.errors, [], "JavaScript errors")
        await self.context.close()
        await self.browser.close()
        await self.pw.stop()
        self.server.should_exit = True
        await asyncio.to_thread(self.thread.join, 4)
        self.assertFalse(self.thread.is_alive(), "Owned API fixture shut down")
        self.db.close()
        self.temp.cleanup()

    async def create_via_dashboard(self):
        await self.page.goto(self.origin + "/dashboard/#queued")
        await self.page.locator("#application").wait_for(state="visible")
        await self.page.locator("#create-button").click()
        form = self.page.locator("#create-form")
        await form.locator('input[name="display_name"]').fill("Regional image classifier")
        await form.locator('select[name="source_id"]').select_option("approved")
        await form.locator('input[name="source_commit"]').fill("a"*40)
        await form.locator('select[name="runtime_image"]').select_option("cpu-image")
        await form.locator('input[name="plugin"]').fill("examples.lenet")
        await form.locator('select[name="pool_id"]').select_option("cpu")
        for suffix in ("a", "b"):
            block = form.locator(".binding-block").filter(
                has=self.page.locator('input[type="checkbox"][value="data-' + suffix + '"]'))
            await block.locator('input[type="checkbox"]').check()
            await block.locator("select[data-mode]").select_option("managed")
            await block.locator('select[data-resource="pool"]').select_option("cpu")
        await self.page.locator("#submit-create").click()
        await self.page.wait_for_url("**#job/*")
        await self.page.locator("#detail-panel .detail-banner").wait_for()
        job_id = self.page.url.split("#job/")[1].split("?")[0]
        return job_id

    async def test_create_waits_for_initial_catalog_and_route(self):
        initial_catalog = asyncio.Event()
        release_catalog = asyncio.Event()
        first_request = True

        async def delay_initial_catalog(route):
            nonlocal first_request
            if first_request:
                first_request = False
                initial_catalog.set()
                await release_catalog.wait()
            await route.continue_()

        await self.page.route("**/api/jobs/v1/catalog", delay_initial_catalog)
        try:
            await self.page.goto(self.origin + "/dashboard/#queued")
            await asyncio.wait_for(initial_catalog.wait(), 5)
            await self.page.locator("#application").wait_for(state="visible")
            self.assertTrue(await self.page.locator("#create-button").is_disabled(),
                            "Creation must wait for the initial catalog and route")
        finally:
            release_catalog.set()

        await self.page.locator("#create-button").click()
        await self.page.locator("#create-dialog").wait_for(state="visible")
        await self.page.locator('#create-form input[name="display_name"]').fill("Ready project")
        self.assertEqual(await self.page.locator("#page-title").inner_text(), "Job queue")
        self.assertEqual(await self.page.locator('#create-form input[name="display_name"]').input_value(),
                         "Ready project")

    async def test_browser_create_log_artifact_access_cancel_and_history(self):
        job_id = await self.create_via_dashboard()
        persisted = self.manager.get_job("alice", job_id)
        self.assertEqual(persisted["name"], "Regional image classifier")
        self.assertEqual(persisted["state"], "QUEUED")
        self.assertEqual(persisted["target_round"], 10)
        self.assertEqual({participant["participant_id"] for participant in persisted["spec"]["participants"]},
                         {"participant-a", "participant-b"})
        self.assertTrue(all(participant["mode"] == "managed" for participant in persisted["spec"]["participants"]))
        self.assertEqual(sum(component["role"] == "participant" for component in persisted["spec"]["components"]), 2)
        self.assertEqual(persisted["spec"]["components"][0]["resources"]["memory_bytes"], 2 << 30)
        self.assertEqual(self.manager.list_jobs("alice")["total"], 1)
        self.assertEqual(self.manager.list_jobs("bob")["total"], 1)
        with self.db.transaction() as session:
            session.add(models.LogChunk(job_id=job_id, component="owner", attempt_number=1, sequence=1, data="<script>alert(1)</script>\nEpoch 1 complete"))
            session.add(models.ProvisioningResource(id="resource-1", job_id=job_id, kind="volume", external_id="fixture-volume", ownership_json={"job_id": job_id}, state="ready"))
            session.add(models.Artifact(id="artifact-1", job_id=job_id, attempt_number=1, kind="checkpoint", name="global-checkpoint.bin", size_bytes=26, sha256="c"*64, storage_key="owned-artifact", locator_json={"kind": "local", "resource_id": "resource-1", "relative_path": "global-checkpoint.bin"}, state="retained", expires_at=utcnow()+timedelta(days=90)))
        await self.page.locator('a[href$="?tab=logs"]').click()
        await self.page.locator("#log-output", has_text="Epoch 1 complete").wait_for()
        self.assertIn("<script>", await self.page.locator("#log-output").inner_text())
        self.assertEqual(await self.page.locator("#log-output script").count(), 0)
        await self.page.locator("#log-attempt").select_option("1")
        await self.page.get_by_role("button", name="Load logs").click()
        await self.page.locator("#log-output", has_text="Epoch 1 complete").wait_for()
        await self.page.locator('a[href$="?tab=artifacts"]').click()
        async with self.page.expect_download() as received:
            await self.page.get_by_role("button", name="Download", exact=True).click()
        download = await received.value
        self.assertEqual(download.suggested_filename, "global-checkpoint.bin")
        self.assertEqual(Path(await download.path()).read_bytes(), b"synthetic-checkpoint-bytes")
        await self.page.locator('a[href$="?tab=access"]').click()
        await self.page.get_by_role("button", name="Grant access").click()
        await self.page.locator('#member-form input[name="principal_id"]').fill("colleague")
        await self.page.locator('#member-form select[name="role"]').select_option("reader")
        await self.page.locator("#submit-member").click()
        await self.page.locator("#detail-panel td", has_text="colleague").wait_for()
        self.assertEqual(self.manager.get_job("colleague", job_id)["id"], job_id)
        await self.page.get_by_role("button", name="Cancel", exact=True).click()
        await self.page.locator("#submit-action").click()
        await self.page.locator("#detail-panel .badge", has_text="Cancelling").first.wait_for()
        self.assertEqual(self.manager.get_job("alice", job_id)["state"], "CANCELLING")
        self.assertTrue(any(event["kind"] == "job.cancel_requested" for event in self.manager.list_events("alice", job_id)["items"]))
        await self.page.locator('a[data-view="queued"]').click()
        await self.page.locator("#jobs-content .empty-state").wait_for()
        self.assertNotIn("Bob private", await self.page.locator("#application").inner_text())
        status = await self.page.evaluate("async (path) => (await fetch(path)).status", "/api/jobs/v1/jobs/"+self.foreign["id"])
        self.assertEqual(status, 404)
        artifacts = Path(os.environ.get("HF2L_DASHBOARD_ARTIFACTS", "/tmp/hf2l-dashboard-artifacts"))
        artifacts.mkdir(parents=True, exist_ok=True)
        await self.page.screenshot(path=str(artifacts / "real-api-dashboard-queue.png"), full_page=True)

    async def test_sse_revocation_clears_visible_detail_and_session_expiry(self):
        job_id = await self.create_via_dashboard()
        await self.page.locator("#connection-label", has_text="Live updates").wait_for()
        with self.db.transaction() as session:
            session.delete(session.get(models.Membership, (job_id, "alice")))
        await self.page.locator("#page-error", has_text="unavailable").wait_for()
        await self.page.locator("#detail-panel .empty-state", has_text="Job unavailable").wait_for()
        self.assertNotIn("Regional image classifier", await self.page.locator("#detail-panel").inner_text())
        self.auth.revoked = True
        await self.page.locator("#login-panel").wait_for(state="visible")
        self.assertFalse(await self.page.locator("#application").is_visible())


if __name__ == "__main__":
    unittest.main()
