"""Focused packaged-dashboard browser checks.

Run on Linux with task-owned Playwright and its Chromium installation. Ordinary
unit discovery skips the browser class if Playwright is not installed; the
static asset checks always run.
"""
from __future__ import annotations

import asyncio
import functools
import http.server
import json
import os
from pathlib import Path
import threading
import unittest
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1] / "src" / "hf2l_jobs" / "static"
try:
    from playwright.async_api import async_playwright
except ImportError:
    if os.environ.get("JOBS_REQUIRE_BROWSER_TESTS") == "1":
        raise
    async_playwright = None


class DashboardAssetTests(unittest.TestCase):
    def test_packaged_html_has_external_scripts_and_styles_only(self):
        html = (ROOT / "index.html").read_text()
        self.assertIn('src="app.js"', html)
        self.assertIn('href="styles.css"', html)
        self.assertNotIn("onclick=", html)
        self.assertNotIn("<style", html)
        self.assertNotIn('style="', html)
        self.assertIn('lang="en"', html)
        self.assertIn('aria-labelledby="create-title"', html)

    def test_no_html_interpolation_or_token_storage(self):
        script = (ROOT / "app.js").read_text()
        for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "localStorage", "sessionStorage", "document.cookie", "eval("):
            self.assertNotIn(forbidden, script)
        self.assertIn('credentials: "same-origin"', script)
        self.assertIn('"X-CSRF-Token"', script)
        self.assertIn('"If-Match"', script)
        self.assertIn('"Idempotency-Key"', script)
        self.assertIn('stream.addEventListener("session_expired"', script)
        self.assertIn('stream.addEventListener("reset"', script)
        self.assertIn("10000", script)


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_):
        pass


@unittest.skipUnless(async_playwright is not None, "task-owned Playwright required")
class DashboardBrowserTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        handler = functools.partial(QuietHandler, directory=str(ROOT))
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = "http://127.0.0.1:" + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    async def asyncSetUp(self):
        self.pw = await async_playwright().start()
        self.browser = await self.pw.chromium.launch(headless=True, args=["--disable-dev-shm-usage"])
        self.context = await self.browser.new_context(viewport={"width": 1440, "height": 1000})
        self.page = await self.context.new_page()
        self.page.set_default_timeout(10000)
        self.errors = []
        self.page.on("pageerror", lambda err: self.errors.append(str(err)))
        self.requests = []
        self.authenticated = True
        self.platform_operator = True
        self.conflict = False
        resources = {"pool_id": "cpu", "cpu_millicores": 1000, "memory_bytes": 2147483648, "disk_bytes": 4294967296, "gpu_count": 0, "gpu_profile": None, "sandbox_profile": "runsc-cpu-v1"}
        self.job_spec = {"project_id": "research", "name": "Regional classifier", "source_id": "approved", "source_commit": "a"*40, "runtime_image": "cpu-image", "plugin": "lenet", "options": {"batch_size": 32}, "secret_refs": {}, "participants": [{"participant_id": "alice", "dataset_binding": "dataset-alice", "mode": "external", "component_id": None}], "components": [{"component_id": "owner", "role": "owner", "participant_id": None, "resources": resources}], "target_round": 10, "max_duration_seconds": 7200}
        def job(jid, status, title, allowed):
            return {"id": jid, "name": title, "version": 3, "state": status, "phase": "waiting_participants" if status == "RUNNING" else "pending", "created_at": "2026-10-09T10:00:00Z", "queued_at": "2026-10-09T10:00:00Z", "current_round": 3 if status == "RUNNING" else 0, "target_round": 10, "cleanup_status": "pending", "space_id": "space-"+jid, "spec_hash": "b"*64, "spec": dict(self.job_spec), "allowed_actions": allowed, "role": "admin", "participants": [{"participant_id": "alice", "mode": "external", "readiness": "ready", "node_id": "node-alice"}], "metrics": {"accuracy": 0.9372}, "queue_reason": "capacity" if status == "QUEUED" else None}
        self.jobs = [job("running-a", "RUNNING", "Regional classifier", ["cancel", "manage_members"]), job("queue-b", "QUEUED", "Queued experiment", ["cancel", "manage_members"]), job("failed-c", "FAILED", "<img src=x onerror=alert(1)>", ["retry", "purge", "reconcile", "manage_members"])]
        self.members = [{"principal_id": "owner", "role": "admin"}]
        self.enrollments = {}
        self.catalog = {"projects": [{"id": "research", "name": "Research"}], "sources": [{"id": "approved", "project_id": "research", "allowed_commits": ["a"*40]}], "runtime_images": [{"id": "cpu-image", "digest": "sha256:"+"b"*64}], "pools": [{"id": "cpu", "name": "CPU lab", "profiles": ["runsc-cpu-v1"]}], "participant_bindings": [{"id": "dataset-alice", "project_id": "research", "participant_id": "alice", "dataset_label": "Approved local images", "node_id": "node-alice"}]}
        await self.page.route("**/api/jobs/v1/**", self.route)
        await self.page.route("**/auth/logout", self.route)

    async def asyncTearDown(self):
        self.assertEqual(self.errors, [], "Browser JavaScript errors")
        await self.context.close()
        await self.browser.close()
        await self.pw.stop()

    async def route(self, route):
        request = route.request
        path = urlparse(request.url).path
        q = parse_qs(urlparse(request.url).query)
        body = request.post_data_json if request.post_data else None
        self.requests.append({"path": path, "method": request.method, "headers": request.headers, "body": body, "query": q})
        async def answer(data, status=200):
            await route.fulfill(status=status, content_type="application/json", body=json.dumps(data))
        if path.endswith("/session"):
            await answer({"authenticated": self.authenticated, "principal": {"principal_id": "owner", "display_name": "Research owner"} if self.authenticated else None, "csrf_token": "csrf-fixture", "permissions": ["platform_operator"] if self.platform_operator else [], "login_url": "/auth/login"})
            return
        if path.endswith("/auth/logout"):
            self.authenticated = False
            await answer({"authenticated": False})
            return
        if not self.authenticated:
            await answer({"error": {"code": "session_expired"}}, 401)
            return
        if path.endswith("/events/stream"):
            await route.fulfill(content_type="text/event-stream", body="event: invalidated\nid: opaque-test-cursor\ndata: {}\n\n")
            return
        if path.endswith("/catalog"):
            await answer(self.catalog)
            return
        if path.endswith("/pools"):
            await answer({"items": [{"id": "cpu", "name": "CPU lab", "node_id": "node-a", "cpu_millicores": 4000, "memory_bytes": 8589934592, "disk_bytes": 17179869184, "qualified_profiles": ["runsc-cpu-v1"], "healthy": True, "quarantined": False, "used": {"cpu_millicores": 2000}, "cleanup_pending": 0}]})
            return
        if path.endswith("/jobs"):
            if request.method == "POST":
                created = {"id": "created-d", "name": body["name"], "state": "QUEUED", "phase": "pending", "version": 1, "spec": body, "created_at": "2026-10-09T10:00:00Z", "current_round": 0, "allowed_actions": ["cancel", "manage_members"]}
                self.jobs.append(created)
                await answer(created, 202)
                return
            view = q.get("view", ["all"])[0]
            jobs = self.jobs
            if view == "current":
                jobs = [j for j in jobs if j["state"] not in {"QUEUED", "FAILED", "CANCELLED", "SUCCEEDED"}]
            elif view == "queued":
                jobs = [j for j in jobs if j["state"] == "QUEUED"]
            elif view == "history":
                jobs = [j for j in jobs if j["state"] in {"FAILED", "CANCELLED", "SUCCEEDED"}]
            if q.get("search"):
                jobs = [j for j in jobs if q["search"][0].lower() in j["name"].lower()]
            if q.get("state"):
                jobs = [j for j in jobs if j["state"] == q["state"][0]]
            await answer({"items": jobs, "next_cursor": None, "counts": {"running": 1, "queued": 1, "preparing": 0, "history": 1}})
            return
        pieces = path.split("/")
        if "jobs" in pieces:
            index = pieces.index("jobs", 3)
            jid = pieces[index + 1] if len(pieces) > index + 1 else ""
            job = next((j for j in self.jobs if j["id"] == jid), None)
            if not job:
                await answer({"error": {"code": "job_not_found"}}, 404)
                return
            suffix = pieces[index+2:]
            if not suffix:
                await answer(job)
            elif suffix[0] == "attempts":
                await answer({"items": [{"id": "attempt-a", "number": 1, "state": "RUNNING", "created_at": "2026-10-09T10:00:00Z"}]})
            elif suffix[0] == "events":
                await answer({"items": [{"kind": "job_created", "created_at": "2026-10-09T10:00:00Z", "detail": {"name": "<svg onload=alert(1)>"}}]})
            elif suffix[0] == "logs":
                await answer({"items": [{"text": "<script>alert(1)</script>\nEpoch 1 complete", "component_id": "owner"}], "next_cursor": None})
            elif suffix[0] == "participants":
                participant = suffix[1]
                if suffix[-1] == "enroll" and request.method == "POST":
                    job["version"] += 1
                    self.enrollments[participant] = {"participant_id": participant, "node_id": body["node_id"], "status": "enrolled", "version": job["version"]}
                    await answer(self.enrollments[participant], 202)
                elif participant in self.enrollments:
                    await answer(self.enrollments[participant])
                else:
                    await answer({"error": {"code": "participant_enrollment_not_found"}}, 404)
            elif suffix[0] == "artifacts":
                if q.get("cursor"):
                    await answer({"items": [{"id": "artifact-more", "name": "metrics.json", "kind": "metrics", "size_bytes": 40, "download_available": False}], "next_cursor": None})
                elif len(suffix) > 1:
                    await answer({"download_url": "/api/jobs/v1/downloads/opaque-artifact"})
                else:
                    await answer({"items": [{"id": "artifact-a", "name": "model.pt", "kind": "checkpoint", "size_bytes": 1234, "sha256": "c"*64, "expires_at": "2099-10-09T10:00:00Z"}, {"id": "old-a", "name": "expired.pt", "expired": True, "sha256": "d"*64}], "next_cursor": "artifact-page-two"})
            elif suffix[0] == "members":
                if request.method == "GET":
                    await answer({"items": self.members})
                elif self.conflict:
                    await answer({"error": {"code": "version_conflict"}}, 409)
                else:
                    principal = suffix[1]
                    self.members = [m for m in self.members if m["principal_id"] != principal]
                    if request.method == "PUT":
                        self.members.append({"principal_id": principal, "role": body["role"]})
                    job["version"] += 1
                    await answer(job)
            elif suffix[0] in {"cancel", "retry", "reconcile", "purge"}:
                if self.conflict:
                    await answer({"error": {"code": "version_conflict"}}, 409)
                else:
                    job["version"] += 1
                    if suffix[0] == "cancel":
                        job["state"] = "CANCELLING"; job["allowed_actions"] = ["manage_members"]
                    await answer(job, 202)
            else:
                await answer({"error": {"code": "unknown_route"}}, 404)
            return
        await answer({"error": {"code": "unknown_route"}}, 404)

    async def go(self, path="#current"):
        await self.page.goto(self.origin + "/index.html" + path)
        await self.page.locator("#application").wait_for(state="visible")
        await self.page.wait_for_function("document.querySelector('#updated-label').textContent.startsWith('Updated') || !document.querySelector('#page-error').hidden")
        await self.page.wait_for_timeout(350)

    async def test_overview_queue_history_and_safe_rendering(self):
        await self.go()
        self.assertEqual(await self.page.locator("#page-title").inner_text(), "Current jobs")
        self.assertEqual(await self.page.locator("#jobs-content .job-name").inner_text(), "Regional classifier")
        await self.page.locator('a[data-view="queued"]').click()
        await self.page.locator("#jobs-content .job-name", has_text="Queued experiment").wait_for()
        self.assertIn("Capacity", await self.page.locator("#jobs-content").inner_text())
        await self.page.locator('a[data-view="history"]').click()
        await self.page.locator("#jobs-content .job-name", has_text="<img").wait_for()
        self.assertEqual(await self.page.locator("#jobs-content img").count(), 0)
        await self.page.locator("#jobs-content .job-name").click()
        await self.page.locator(".timeline-detail").wait_for()
        self.assertEqual(await self.page.locator("#detail-panel svg").count(), 0)
        self.assertNotIn("[object HTML", await self.page.locator("#detail-panel").inner_text())
        self.assertIn("runsc-cpu-v1", await self.page.locator("#detail-panel").inner_text())
        self.assertIn("<svg", await self.page.locator(".timeline-detail").inner_text())
        self.assertEqual(await self.page.evaluate("Object.keys(localStorage).length + Object.keys(sessionStorage).length"), 0)
        artifacts = Path(os.environ.get("HF2L_DASHBOARD_ARTIFACTS", "/tmp/hf2l-dashboard-artifacts"))
        artifacts.mkdir(parents=True, exist_ok=True)
        await self.page.screenshot(path=str(artifacts / "job-detail-desktop.png"), full_page=True)
        await self.page.set_viewport_size({"width": 390, "height": 844})
        await self.page.screenshot(path=str(artifacts / "job-detail-mobile.png"), full_page=True)
        self.assertLessEqual(await self.page.evaluate("document.documentElement.scrollWidth"), 390)

    async def test_create_spec_managed_participant_and_csrf(self):
        await self.go()
        await self.page.locator("#create-button").click()
        form = self.page.locator("#create-form")
        await form.locator('input[name="display_name"]').fill("New research job")
        await form.locator('select[name="source_id"]').select_option("approved")
        await form.locator('input[name="source_commit"]').fill("a"*40)
        await form.locator('select[name="runtime_image"]').select_option("cpu-image")
        await form.locator('input[name="plugin"]').fill("lenet")
        await form.locator('select[name="pool_id"]').select_option("cpu")
        await form.locator('input[type="checkbox"]').check()
        await form.locator('[data-mode]').select_option("managed")
        await form.locator('[data-resource="pool"]').select_option("cpu")
        await self.page.locator("#submit-create").click()
        await self.page.wait_for_url("**#job/created-d")
        creation = next(r for r in self.requests if r["path"].endswith("/jobs") and r["method"] == "POST")
        self.assertEqual(creation["headers"]["x-csrf-token"], "csrf-fixture")
        self.assertTrue(creation["headers"]["idempotency-key"])
        self.assertNotIn("if-match", creation["headers"])
        self.assertEqual(creation["body"]["target_round"], 10)
        self.assertEqual(creation["body"]["max_duration_seconds"], 7200)
        self.assertEqual(creation["body"]["participants"][0]["mode"], "managed")
        self.assertEqual(len(creation["body"]["components"]), 2)
        self.assertEqual(creation["body"]["components"][1]["resources"]["sandbox_profile"], "runsc-cpu-v1")

    async def test_log_text_access_controls_and_lifecycle_headers(self):
        await self.go("#job/running-a?tab=logs")
        await self.page.locator("#log-output", has_text="Epoch 1").wait_for()
        self.assertIn("<script>", await self.page.locator("#log-output").inner_text())
        self.assertEqual(await self.page.locator("#log-output script").count(), 0)
        await self.page.locator('a[href$="?tab=overview"]').click()
        await self.page.get_by_role("button", name="Enroll", exact=True).click()
        self.assertEqual(await self.page.locator('input[name="enrollment_node"]').input_value(), "node-alice")
        await self.page.locator("#submit-action").click()
        await self.page.locator("#detail-panel .secondary", has_text="Enrolled").wait_for()
        enrollment = next(r for r in self.requests if r["path"].endswith("/enroll"))
        self.assertEqual(enrollment["body"], {"node_id": "node-alice"})
        self.assertEqual(enrollment["headers"]["if-match"], '"3"')
        await self.page.locator('a[href$="?tab=artifacts"]').click()
        await self.page.get_by_role("button", name="Load more artifacts").click()
        await self.page.locator("#detail-panel .job-name", has_text="metrics.json").wait_for()
        self.assertIn("Unavailable", await self.page.locator("#detail-panel").inner_text())
        await self.page.locator('a[href$="?tab=access"]').click()
        await self.page.get_by_role("button", name="Grant access").click()
        await self.page.locator('#member-form input[name="principal_id"]').fill("colleague")
        await self.page.locator('#member-form select[name="role"]').select_option("operator")
        await self.page.locator("#submit-member").click()
        await self.page.locator("#detail-panel td", has_text="colleague").wait_for()
        mutation = next(r for r in self.requests if r["method"] == "PUT")
        self.assertEqual(mutation["headers"]["if-match"], '"4"')
        self.assertEqual(mutation["headers"]["x-csrf-token"], "csrf-fixture")
        await self.page.get_by_role("button", name="Cancel", exact=True).click()
        await self.page.locator("#submit-action").click()
        await self.page.locator("#detail-panel .badge", has_text="Cancelling").first.wait_for()
        cancel = next(r for r in self.requests if r["path"].endswith("/cancel"))
        self.assertEqual(cancel["headers"]["if-match"], '"5"')
        self.assertTrue(cancel["headers"]["idempotency-key"])

    async def test_conflict_preserves_action_and_purge_confirmation(self):
        await self.go("#job/failed-c")
        await self.page.get_by_role("button", name="Purge", exact=True).click()
        await self.page.locator("#submit-action").click()
        await self.page.locator("#action-error", has_text="exact job ID").wait_for()
        self.assertFalse(any(r["path"].endswith("/purge") for r in self.requests))
        await self.page.locator('#action-form input[name="confirmation"]').fill("failed-c")
        self.conflict = True
        await self.page.locator("#submit-action").click()
        await self.page.locator("#action-error", has_text="Refresh").wait_for()
        self.assertTrue(await self.page.locator("#action-dialog").is_visible())
        mutation = next(r for r in self.requests if r["path"].endswith("/purge"))
        self.assertEqual(mutation["headers"]["if-match"], '"3"')

    async def test_operator_health_and_expired_session(self):
        await self.go("#operations")
        await self.page.get_by_role("heading", name="CPU lab").wait_for()
        self.assertIn("runsc-cpu-v1", await self.page.locator("#operations-panel").inner_text())
        self.authenticated = False
        await self.page.locator("#refresh-button").click()
        await self.page.locator("#login-panel").wait_for(state="visible")
        self.assertFalse(await self.page.locator("#application").is_visible())
        self.assertIn("Sign in", await self.page.locator("#login-panel").inner_text())

    async def test_nonoperator_cannot_query_operational_inventory(self):
        self.platform_operator = False
        await self.go("#operations")
        self.assertFalse(await self.page.locator("#operations-link").is_visible())
        await self.page.locator("#page-error", has_text="Platform operator").wait_for()
        self.assertFalse(any(r["path"].endswith("/pools") for r in self.requests))


if __name__ == "__main__":
    unittest.main()
