"""HTTP acceptance tests with the real persistent manager and test-only identity."""
from __future__ import annotations

import json
import base64
import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from contextlib import asynccontextmanager

from fastapi.testclient import TestClient

from hf2l_jobs.api import create_app, StreamCursor
from hf2l_jobs.application import Manager
from hf2l_jobs.database import create_database
from hf2l_jobs.domain import Error
from hf2l_jobs import models

BASE = "/api/jobs/v1"
COMMIT = "a" * 40


class TestAuth:
    """Only the identity boundary is replaced; all job ACLs remain real."""
    def __init__(self):
        self.calls = 0
        self.expire_after = None
        self.on_auth = None

    def authenticate_request(self, authorization="", session_token="", touch=True):
        self.calls += 1
        if self.expire_after is not None and self.calls > self.expire_after:
            raise Error(401, "session_expired")
        if self.on_auth:
            self.on_auth(self.calls)
        actor = authorization.removeprefix("Bearer ") if authorization else session_token
        if actor not in {"alice", "bob", "platform"}:
            raise Error(401, "authentication_required")
        return SimpleNamespace(id=actor, display_name=actor,
                               platform_operator=actor == "platform")

    def require_csrf(self, token, csrf, origin=""):
        if csrf != "csrf-" + token or origin != "https://testserver":
            raise Error(403, "csrf_required")

    def session_info(self, token):
        actor = self.authenticate_request(session_token=token)
        return {"authenticated": True, "principal": {"principal_id": actor.id,
                "display_name": actor.id}, "csrf_token": "csrf-" + token,
                "permissions": [], "login_url": "/auth/login"}

    def begin_login(self):
        return SimpleNamespace(authorization_url="https://id.example/auth", state_cookie="bound")

    def finish_login(self, code, state, cookie):
        if (code, state, cookie) != ("valid", "state", "bound"):
            raise Error(401, "invalid_login_state")
        return SimpleNamespace(session_token="alice", csrf_token="csrf-alice",
                               principal=SimpleNamespace(id="alice"))

    def logout(self, token, csrf, origin=""):
        self.require_csrf(token, csrf, origin)

    def backchannel_logout(self, token):
        if token != "signed-logout":
            raise Error(401, "invalid_logout_token")

    def authenticate_node(self, authorization, peer_thumbprint):
        if authorization != "Bearer node" or peer_thumbprint != "verified":
            raise Error(401, "invalid_node_grant")
        return SimpleNamespace(node_id="node1", pool_id="pool", job_id="job",
            attempt_id="attempt", component_id="owner", epoch=1,
            scopes={"acknowledge", "heartbeat", "progress", "logs", "stopped"})


class NodeController:
    """Test the HTTP node binding checks, not the scheduler implementation."""
    def check_assignment(self, node, pool, job, attempt, component, epoch):
        return (node, pool, job, attempt, component, epoch) == (
            "node1", "pool", "job", "attempt", "owner", 1)

    def ack_assignment(self, *args):
        return True


class APIAcceptance(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = create_database("sqlite:///" + str(Path(self.temp.name) / "manager.sqlite"))
        with self.db.transaction() as session:
            session.add(models.Project(id="project", name="Example project", quotas_json={
                "cpu_millicores": 4000, "memory_bytes": 8 << 30, "disk_bytes": 8 << 30}))
            session.flush()
            for actor in ("alice", "bob"):
                session.add(models.ProjectMember(project_id="project", principal_id=actor, role="submitter"))
            session.add(models.ApprovedSource(id="source", project_id="project",
                name="Approved code", url="https://github.com/example/repo.git",
                allowed_commits=[COMMIT], allowed_hosts=["github.com"], enabled=True))
            session.add(models.RuntimeImage(id="image", digest="sha256:" + "b" * 64, enabled=True))
            for suffix, node_id in [("alice", "external-node"), ("bob", "external-node-bob")]:
                session.add(models.ParticipantBinding(id="data-" + suffix, project_id="project",
                    participant_id=suffix + "-data", node_id=node_id,
                    dataset_label="Approved " + suffix + " local data", enabled=True))
            session.add(models.Pool(id="pool", name="CPU", node_id="node1",
                cpu_millicores=4000, memory_bytes=8 << 30, disk_bytes=8 << 30,
                sandbox_profiles=["runsc-cpu-v1"], healthy=True, quarantined=False))
        self.manager = Manager(self.db, "c" * 32, platform_operator_ids=("platform",))
        self.auth = TestAuth()
        self.app = create_app(self.manager, self.auth, cursor_secret="c" * 32,
                              controller=NodeController(), sse_poll_seconds=.05)
        self.client = TestClient(self.app, base_url="https://testserver")

    def tearDown(self):
        self.client.close()
        self.db.close()
        self.temp.cleanup()

    @staticmethod
    def spec(name="Experiment"):
        return {"project_id": "project", "name": name, "source_id": "source",
                "source_commit": COMMIT, "runtime_image": "image", "plugin": "examples.lenet",
                "options": {}, "participants": [
                    {"participant_id": "alice-data", "dataset_binding": "data-alice", "mode": "external"},
                    {"participant_id": "bob-data", "dataset_binding": "data-bob", "mode": "external"}],
                "target_round": 3,
                "max_duration_seconds": 3600, "components": [{"component_id": "owner",
                "role": "owner", "resources": {"pool_id": "pool", "cpu_millicores": 1000,
                "memory_bytes": 1 << 30, "disk_bytes": 1 << 30}}]}

    @staticmethod
    def headers(actor="alice", key=None, version=None):
        result = {"Authorization": "Bearer " + actor}
        if key is not None:
            result["Idempotency-Key"] = key
        if version is not None:
            result["If-Match"] = '"' + str(version) + '"'
        return result

    def create(self, actor="alice", key="create", name="Experiment"):
        response = self.client.post(BASE + "/jobs", json=self.spec(name),
                                    headers=self.headers(actor, key))
        self.assertEqual(response.status_code, 202, response.text)
        return response.json()

    def test_create_is_durable_idempotent_and_reports_detail_location(self):
        first = self.client.post(BASE + "/jobs", json=self.spec(), headers=self.headers(key="same"))
        second = self.client.post(BASE + "/jobs", json=self.spec(), headers=self.headers(key="same"))
        self.assertEqual(first.status_code, 202, first.text)
        self.assertEqual(first.json(), second.json())
        self.assertEqual(first.headers["etag"], '"1"')
        self.assertEqual(first.headers["location"], BASE + "/jobs/" + first.json()["id"])
        changed = self.client.post(BASE + "/jobs", json=self.spec("Different"),
                                   headers=self.headers(key="same"))
        self.assertEqual(changed.status_code, 409)
        self.assertEqual(changed.json()["error"]["code"], "idempotency_conflict")
        with self.db.transaction() as session:
            self.assertEqual(len(list(session.query(models.Job))), 1)

    def test_lists_counts_pages_and_cursor_binding_hide_foreign_jobs(self):
        alice = [self.create(key="a" + str(i), name="Alice " + str(i)) for i in range(3)]
        foreign = self.create(actor="bob", key="b", name="Secret Bob")
        response = self.client.get(BASE + "/jobs?limit=1&view=queued", headers=self.headers())
        self.assertEqual(response.status_code, 200, response.text)
        page = response.json()
        self.assertEqual(page["total"], 3)
        self.assertEqual(page["counts"], {"queued": 3, "current": 0, "history": 0})
        self.assertNotIn(foreign["id"], response.text)
        ids = {page["items"][0]["id"]}
        cursor = page["next_cursor"]
        while cursor:
            response = self.client.get(BASE + "/jobs", params={"limit": 1, "view": "queued",
                "cursor": cursor}, headers=self.headers())
            self.assertEqual(response.status_code, 200, response.text)
            page = response.json()
            ids.update(value["id"] for value in page["items"])
            cursor = page["next_cursor"]
        self.assertEqual(ids, {value["id"] for value in alice})
        first_cursor = self.client.get(BASE + "/jobs?limit=1&view=queued",
            headers=self.headers()).json()["next_cursor"]
        for headers, view in [(self.headers("bob"), "queued"), (self.headers(), "history")]:
            bad = self.client.get(BASE + "/jobs", params={"cursor": first_cursor,
                "view": view}, headers=headers)
            self.assertIn(bad.status_code, (400, 409, 422))

    def test_foreign_detail_history_and_mutations_are_concealed(self):
        job = self.create(actor="bob")
        for suffix in ("", "/attempts", "/events", "/logs", "/members", "/artifacts"):
            response = self.client.get(BASE + "/jobs/" + job["id"] + suffix,
                                       headers=self.headers())
            self.assertEqual(response.status_code, 404, (suffix, response.text))
            self.assertNotIn("Experiment", response.text)
        response = self.client.post(BASE + "/jobs/" + job["id"] + "/cancel",
                                    headers=self.headers(key="cancel", version=1))
        self.assertEqual(response.status_code, 404)

    def test_mutations_require_version_and_key_and_replay_same_result(self):
        job = self.create()
        url = BASE + "/jobs/" + job["id"] + "/cancel"
        missing = self.client.post(url, headers=self.headers(key="cancel"))
        self.assertEqual(missing.status_code, 428)
        missing_key = self.client.post(url, headers=self.headers(version=1))
        self.assertEqual(missing_key.status_code, 400)
        weak = self.client.post(url, headers={**self.headers(key="cancel"), "If-Match": 'W/"1"'})
        self.assertEqual(weak.status_code, 400)
        first = self.client.post(url, headers=self.headers(key="cancel", version=1))
        replay = self.client.post(url, headers=self.headers(key="cancel", version=1))
        self.assertEqual(first.status_code, 202, first.text)
        self.assertEqual(first.json(), replay.json())
        self.assertEqual(first.json()["state"], "CANCELLING")
        stale = self.client.post(url, headers=self.headers(key="other", version=1))
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(stale.json()["error"]["code"], "job_version_conflict")

    def test_membership_revocation_affects_existing_identity_immediately(self):
        job = self.create()
        url = BASE + "/jobs/" + job["id"]
        grant = self.client.put(url + "/members/bob", json={"role": "reader"},
                               headers=self.headers(key="grant", version=1))
        self.assertEqual(grant.status_code, 200, grant.text)
        self.assertEqual(self.client.get(url, headers=self.headers("bob")).status_code, 200)
        forbidden = self.client.post(url + "/cancel", headers=self.headers("bob", "cancel", 2))
        self.assertEqual(forbidden.status_code, 403)
        revoke = self.client.delete(url + "/members/bob", headers=self.headers(key="revoke", version=2))
        self.assertEqual(revoke.status_code, 200, revoke.text)
        self.assertEqual(self.client.get(url, headers=self.headers("bob")).status_code, 404)
        last_admin = self.client.delete(url + "/members/alice", headers=self.headers(key="last", version=3))
        self.assertEqual(last_admin.status_code, 409)

    def test_sessions_csrf_cookie_flags_and_security_headers(self):
        self.assertFalse(self.client.get(BASE + "/session").json()["authenticated"])
        start = self.client.get("/auth/login", follow_redirects=False)
        self.assertEqual(start.status_code, 303)
        cookie = start.headers["set-cookie"]
        for flag in ("Secure", "HttpOnly", "SameSite=lax", "Path=/"):
            self.assertIn(flag, cookie)
        callback = self.client.get("/auth/callback?code=valid&state=state", follow_redirects=False)
        self.assertEqual(callback.status_code, 303, callback.text)
        session = self.client.get(BASE + "/session").json()
        self.assertEqual(session["csrf_token"], "csrf-alice")
        denied = self.client.post(BASE + "/jobs", json=self.spec(),
                                  headers={"Idempotency-Key": "browser"})
        self.assertEqual(denied.status_code, 403)
        accepted = self.client.post(BASE + "/jobs", json=self.spec(), headers={
            "Idempotency-Key": "browser", "X-CSRF-Token": "csrf-alice", "Origin": "https://testserver"})
        self.assertEqual(accepted.status_code, 202, accepted.text)
        self.assertEqual(accepted.headers["x-content-type-options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", accepted.headers["content-security-policy"])
        self.assertNotIn("session_token", accepted.text)

    def test_callback_error_clears_one_time_login_cookie(self):
        response = self.client.get("/auth/callback?error=denied", follow_redirects=False)
        self.assertEqual(response.status_code, 400)
        self.assertIn("Max-Age=0", response.headers["set-cookie"])

    def test_backchannel_logout_requires_signed_token_and_bounded_form(self):
        response = self.client.post("/auth/backchannel-logout", data={"logout_token": "signed-logout"})
        self.assertEqual(response.status_code, 200)
        response = self.client.post("/auth/backchannel-logout", data={"logout_token": "unsigned"})
        self.assertEqual(response.status_code, 401)
        response = self.client.post("/auth/backchannel-logout", json={"logout_token": "signed-logout"})
        self.assertEqual(response.status_code, 415)

    def test_rejected_payloads_do_not_echo_secrets_and_limit_body_memory(self):
        body = self.spec()
        body["options"] = {"password": "do-not-echo-this"}
        response = self.client.post(BASE + "/jobs", json=body, headers=self.headers(key="bad"))
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("do-not-echo-this", response.text)
        large = self.client.post(BASE + "/jobs", content=b"x" * 1_048_577, headers=self.headers(key="large"))
        self.assertEqual(large.status_code, 413)

    def test_stream_rechecks_session_and_cursor_has_no_shared_event_sequence(self):
        self.create()
        self.auth.calls = 0
        self.auth.expire_after = 1
        response = self.client.get(BASE + "/events/stream", headers=self.headers())
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("event: invalidated", response.text)
        self.assertIn("event: session_expired", response.text)
        identity = next(line[4:] for line in response.text.splitlines() if line.startswith("id: "))
        self.assertFalse(identity.isdecimal())
        self.assertNotIn('"job_id"', response.text)
        self.auth.calls = 0
        wrong = self.client.get(BASE + "/events/stream", headers={
            **self.headers("bob"), "Last-Event-ID": identity})
        self.assertEqual(wrong.status_code, 400)

    def test_expired_stream_cursor_sends_explicit_reset(self):
        with patch("hf2l_jobs.api.time.time", return_value=0):
            identity = StreamCursor("c" * 32).issue("alice")
        self.auth.calls = 0
        self.auth.expire_after = 1
        response = self.client.get(BASE + "/events/stream", headers={
            **self.headers(), "Last-Event-ID": identity})
        self.assertEqual(response.status_code, 200)
        self.assertIn("event: reset", response.text)

    def test_platform_role_does_not_grant_job_content(self):
        job = self.create()
        response = self.client.get(BASE + "/jobs", headers=self.headers("platform"))
        self.assertEqual(response.json()["total"], 0)
        self.assertEqual(self.client.get(BASE + "/jobs/" + job["id"],
                                        headers=self.headers("platform")).status_code, 404)

    def test_catalog_contains_only_approved_creation_inputs_not_source_credentials(self):
        response = self.client.get(BASE + "/catalog", headers=self.headers())
        self.assertEqual(response.status_code, 200, response.text)
        catalog = response.json()
        self.assertEqual(catalog["projects"][0]["id"], "project")
        self.assertEqual(catalog["sources"][0]["allowed_commits"], [COMMIT])
        self.assertEqual(catalog["runtime_images"][0]["id"], "image")
        self.assertNotIn("github.com", response.text)
        invisible = self.client.get(BASE + "/catalog", headers=self.headers("platform")).json()
        self.assertEqual(invisible["projects"], [])
        self.assertEqual(invisible["sources"], [])

    def test_operator_pool_inventory_and_updates_require_configured_role(self):
        denied = self.client.get(BASE + "/pools", headers=self.headers())
        self.assertEqual(denied.status_code, 403)
        inventory = self.client.get(BASE + "/pools", headers=self.headers("platform"))
        self.assertEqual(inventory.status_code, 200, inventory.text)
        row = inventory.json()["items"][0]
        self.assertEqual(row["reserved"]["cpu_millicores"], 0)
        change = self.client.put(BASE + "/pools/pool", json={"cpu_millicores": 3500},
            headers=self.headers("platform", version=row["version"]))
        self.assertEqual(change.status_code, 200, change.text)
        self.assertEqual(change.json()["cpu_millicores"], 3500)
        stale = self.client.put(BASE + "/pools/pool", json={"healthy": False},
            headers=self.headers("platform", version=row["version"]))
        self.assertEqual(stale.status_code, 409)
        unknown = self.client.put(BASE + "/pools/pool", json={"command": "unsafe"},
            headers=self.headers("platform"))
        self.assertEqual(unknown.status_code, 422)

    def test_current_queued_history_views_and_attempt_event_log_routes(self):
        queued = self.create(key="queued")
        running = self.create(key="running")
        past = self.create(key="past")
        with self.db.transaction() as session:
            session.get(models.Job, running["id"]).state = "RUNNING"
            session.get(models.Job, past["id"]).state = "FAILED"
        for view, identity in [("queued", queued["id"]), ("current", running["id"]), ("history", past["id"])]:
            result = self.client.get(BASE + "/jobs", params={"view": view}, headers=self.headers())
            self.assertEqual([j["id"] for j in result.json()["items"]], [identity])
        root = BASE + "/jobs/" + queued["id"]
        attempts = self.client.get(root + "/attempts", headers=self.headers()).json()
        self.assertEqual(attempts["items"][0]["number"], 1)
        events = self.client.get(root + "/events", headers=self.headers()).json()
        self.assertEqual(events["items"][0]["kind"], "job.created")
        logs = self.client.get(root + "/logs?attempt=1", headers=self.headers())
        self.assertEqual(logs.status_code, 200, logs.text)
        self.assertEqual(logs.json()["items"], [])

    def test_create_requires_approved_default_quorum_before_allocating_resources(self):
        for count in (0, 1):
            with self.subTest(participants=count):
                spec = self.spec("Insufficient participants")
                spec["participants"] = spec["participants"][:count]
                response = self.client.post(BASE + "/jobs", json=spec,
                    headers=self.headers(key="insufficient-" + str(count)))
                self.assertEqual(response.status_code, 422, response.text)
        spec = self.spec("Declared quorum exceeds bindings")
        spec["options"] = {"minimum_participants": 3}
        response = self.client.post(BASE + "/jobs", json=spec,
            headers=self.headers(key="excessive-quorum"))
        self.assertEqual(response.status_code, 422, response.text)
        with self.db.transaction(immediate=False) as session:
            for entity in (models.Job, models.Attempt, models.Allocation, models.ProvisioningResource):
                self.assertEqual(session.query(entity).count(), 0)
        accepted = self.create(key="valid-default-quorum")
        self.assertEqual(len(accepted["spec"]["participants"]), 2)

    def test_artifact_download_is_attachment_and_cannot_reveal_private_origin(self):
        job = self.create()
        with self.db.transaction() as session:
            session.add(models.Artifact(id="artifact", job_id=job["id"], kind="checkpoint",
                name="model.html", size_bytes=4, sha256="d" * 64,
                storage_key="private-origin-credentials/never-expose", state="available",
                locator_json={"kind": "local", "resource_id": "retained-root", "relative_path": "model.html"}))

        class Broker:
            @asynccontextmanager
            async def open_authorized(self, actor, job_id, artifact_id):
                async def chunks():
                    yield b"data"
                yield SimpleNamespace(name="model.html", size=4, chunks=chunks())

        app = create_app(self.manager, self.auth, cursor_secret="c" * 32, artifact_broker=Broker())
        with TestClient(app, base_url="https://testserver") as client:
            root = BASE + "/jobs/" + job["id"] + "/artifacts/artifact"
            metadata = client.get(root, headers=self.headers())
            self.assertNotIn("private-origin", metadata.text)
            download = client.get(root + "/download", headers=self.headers())
            self.assertEqual(download.status_code, 200, download.text)
            self.assertEqual(download.content, b"data")
            self.assertEqual(download.headers["content-type"], "application/octet-stream")
            self.assertTrue(download.headers["content-disposition"].startswith("attachment;"))
            denied = client.get(root + "/download", headers=self.headers("bob"))
            self.assertEqual(denied.status_code, 404)

    def test_artifact_pages_are_acl_bound_and_expose_only_available_capability(self):
        job = self.create()
        with self.db.transaction() as session:
            for index in range(3):
                session.add(models.Artifact(id="artifact-" + str(index), job_id=job["id"],
                    kind="checkpoint", name="model-" + str(index), size_bytes=4,
                    sha256="d" * 64, storage_key="private-never-expose", state="available",
                    locator_json={"kind": "local", "resource_id": "retained-root", "relative_path": "model"}))
        root = BASE + "/jobs/" + job["id"] + "/artifacts"
        first = self.client.get(root, params={"limit": 1}, headers=self.headers())
        self.assertEqual(first.status_code, 200, first.text)
        page = first.json()
        self.assertEqual(len(page["items"]), 1)
        self.assertTrue(page["next_cursor"])
        self.assertFalse(page["items"][0]["download_available"])
        self.assertEqual(page["items"][0]["unavailable_reason"], "artifact_broker_unavailable")
        self.assertNotIn("private-never-expose", first.text)
        second = self.client.get(root, params={"limit": 1, "cursor": page["next_cursor"]}, headers=self.headers())
        self.assertEqual(second.status_code, 200, second.text)
        self.assertNotEqual(second.json()["items"][0]["id"], page["items"][0]["id"])
        foreign = self.client.get(root, params={"cursor": page["next_cursor"]}, headers=self.headers("bob"))
        self.assertEqual(foreign.status_code, 404)
        detail = self.client.get(root + "/" + page["items"][0]["id"], headers=self.headers())
        self.assertFalse(detail.json()["download_available"])
        self.assertEqual(self.client.get(root + "/" + page["items"][0]["id"] + "/download",
            headers=self.headers()).status_code, 503)

    def test_internal_node_route_rejects_forwarded_certificate_spoof(self):
        url = "/internal/jobs/v1/assignments/job/attempt/owner/1/ack"
        response = self.client.post(url, headers={"Authorization": "Bearer node",
            "X-Verified-Peer-Thumbprint": "verified", "X-SSL-Client-Cert": "pretend"})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["error"]["code"], "verified_node_certificate_required")

    def test_node_callbacks_verify_real_assignment_and_persist_bounded_logs(self):
        from hf2l_jobs.controller import Controller
        job = self.create()
        with self.db.transaction() as session:
            stored = session.get(models.Job, job["id"])
            stored.epoch, stored.state = 1, "PROVISIONING"
            attempt = session.query(models.Attempt).filter_by(job_id=job["id"], number=1).one()
            attempt.state, attempt.epoch = "PROVISIONING", 1
            attempt_id = attempt.id
            session.add(models.Allocation(id="allocation", job_id=job["id"], attempt_id=attempt_id,
                component_id="owner", pool_id="pool", cpu_millicores=1000,
                memory_bytes=1 << 30, disk_bytes=1 << 30, epoch=1, state="RESERVED"))
        actor = SimpleNamespace(node_id="node1", pool_id="pool", job_id=job["id"],
            attempt_id=attempt_id, component_id="owner", epoch=1,
            scopes={"acknowledge", "heartbeat", "progress", "logs", "stopped"})
        self.auth.authenticate_node = lambda authorization, peer: actor
        controller = Controller(self.db, object(), object())
        app = create_app(self.manager, self.auth, controller=controller, cursor_secret="c" * 32)

        class VerifiedTLS:
            def __init__(self, inner):
                self.inner = inner
            async def __call__(self, scope, receive, send):
                scope["hf2l.verified_peer_thumbprint"] = "verified"
                await self.inner(scope, receive, send)

        root = "/internal/jobs/v1/assignments/" + job["id"] + "/" + attempt_id + "/owner/1"
        with TestClient(VerifiedTLS(app), base_url="https://testserver") as client:
            for endpoint, payload in [("ack", None), ("heartbeat", None),
                ("progress", {"current_round": 1, "phase": "aggregating", "publication_status": "published",
                              "metrics": {"loss": .25, "samples": 10}, "readiness": "ready"}),
                ("logs", {"entries": ["first line", "second line"]})]:
                response = client.post(root + "/" + endpoint, json=payload,
                                       headers={"Authorization": "Bearer node"})
                self.assertEqual(response.status_code, 200, (endpoint, response.text))
            telemetry = client.post(root + "/progress", json={"publication_status": "not_observed"},
                headers={"Authorization": "Bearer node"})
            self.assertEqual(telemetry.status_code, 200, telemetry.text)
            with self.db.transaction() as session:
                stored_attempt = session.get(models.Attempt, attempt_id)
                self.assertEqual(stored_attempt.details_json["components"]["owner"]["publication_status"], "not_observed")
                self.assertEqual(session.get(models.Job, job["id"]).current_round, 0)
            invalid_metric = client.post(root + "/progress", json={"current_round": 1,
                "phase": "training", "metrics": {"loss": True}},
                headers={"Authorization": "Bearer node"})
            self.assertEqual(invalid_metric.status_code, 422)
            oversized = client.post(root + "/logs", json={"entries": ["x" * 8193]},
                                    headers={"Authorization": "Bearer node"})
            self.assertEqual(oversized.status_code, 413)
            foreign = client.post(root.replace("/owner/1", "/foreign/1") + "/heartbeat",
                                  headers={"Authorization": "Bearer node"})
            self.assertEqual(foreign.status_code, 404)
            stale = client.post(root.replace("/owner/1", "/owner/2") + "/heartbeat",
                                headers={"Authorization": "Bearer node"})
            self.assertEqual(stale.status_code, 404)
            actor.pool_id = "foreign-pool"
            wrong_pool = client.post(root + "/heartbeat", headers={"Authorization": "Bearer node"})
            self.assertEqual(wrong_pool.status_code, 404)
            actor.pool_id = "pool"
            stopped = client.post(root + "/stopped", headers={"Authorization": "Bearer node"})
            self.assertEqual(stopped.status_code, 200, stopped.text)
        with self.db.transaction() as session:
            chunk = session.query(models.LogChunk).one()
            self.assertEqual(chunk.data, "first line\nsecond line")
            self.assertEqual(chunk.job_id, job["id"])
            self.assertTrue(session.get(models.Allocation, "allocation").termination_confirmed)

    def test_managed_bootstrap_and_introspection_use_real_broker_and_durable_allocation(self):
        from datetime import datetime, timedelta, timezone
        from cryptography.hazmat.primitives.asymmetric import rsa
        from hf2l_jobs.broker import BrokerSettings, WorkloadBroker
        from hf2l_jobs.managed_nodes import NodeAssignmentService
        job = self.create()
        limits = {"cpu_millicores": 1000, "memory_bytes": 1 << 30, "disk_bytes": 1 << 30}
        with self.db.transaction() as session:
            stored = session.get(models.Job, job["id"])
            stored.epoch, stored.state = 1, "PROVISIONING"
            stored.deadline_at = datetime.now(timezone.utc) + timedelta(hours=1)
            attempt = session.query(models.Attempt).filter_by(job_id=job["id"], number=1).one()
            attempt.state, attempt.epoch = "PROVISIONING", 1
            attempt_id = attempt.id
            session.add(models.Allocation(id="managed-allocation", job_id=job["id"], attempt_id=attempt_id,
                component_id="owner", pool_id="pool", epoch=1, state="ACKNOWLEDGED", acknowledged=True, **limits))
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        broker = WorkloadBroker(BrokerSettings("https://workload.example", "exchange-aud", "gateway-aud",
                                              "node-aud", key.public_key(), key))
        node_thumb = base64.urlsafe_b64encode(b"n" * 32).decode().rstrip("=")
        manager_thumb = base64.urlsafe_b64encode(b"m" * 32).decode().rstrip("=")
        service = NodeAssignmentService(self.db, object(), broker, {"node1": {"pool_id": "pool",
            "certificate_thumbprint": node_thumb, "registration_id": "registered-node"}},
            manager_certificate_thumbprint=manager_thumb)
        app = create_app(self.manager, self.auth, managed_nodes=service, cursor_secret="c" * 32)

        class VerifiedTLS:
            def __init__(self, inner):
                self.inner, self.thumb = inner, node_thumb
            async def __call__(self, scope, receive, send):
                scope.setdefault("state", {})["verified_certificate_thumbprint"] = self.thumb
                await self.inner(scope, receive, send)

        transport = VerifiedTLS(app)
        root = "/internal/jobs/v1/nodes/" + job["id"] + "/" + attempt_id + "/owner/1"
        with TestClient(transport, base_url="https://testserver") as client:
            bootstrap = client.post(root + "/bootstrap", json={})
            self.assertEqual(bootstrap.status_code, 200, bootstrap.text)
            self.assertNotIn("PRIVATE KEY", bootstrap.text)
            token = bootstrap.json()["token"]
            headers = {"Authorization": "Bearer " + token}
            ambiguous = client.post(root + "/bootstrap", json={}, headers=headers)
            self.assertEqual(ambiguous.status_code, 401)
            body = {"node_id": "node1", "pool_id": "pool", "grant_id": "managed-allocation",
                    "certificate_thumbprint": manager_thumb, "scopes": ["inspect"], "resources": limits}
            accepted = client.post(root + "/validate", json=body, headers=headers)
            self.assertEqual(accepted.status_code, 200, accepted.text)
            self.assertTrue(accepted.json()["valid"])
            oversized = client.post(root + "/validate", json={**body,
                "resources": {**limits, "cpu_millicores": 2000}}, headers=headers)
            self.assertFalse(oversized.json()["valid"])
            foreign_grant = client.post(root + "/validate", json={**body, "grant_id": "other"}, headers=headers)
            self.assertFalse(foreign_grant.json()["valid"])
            forbidden_scope = client.post(root + "/validate", json={**body, "scopes": ["jobs.admin"]}, headers=headers)
            self.assertEqual(forbidden_scope.status_code, 422)
            missing_grant = client.post(root + "/credentials", json={"certificate_thumbprint": node_thumb,
                "audience": "exchange"}, headers=headers)
            self.assertEqual(missing_grant.status_code, 409, missing_grant.text)
            malformed_audience = client.post(root + "/credentials", json={"certificate_thumbprint": node_thumb,
                "audience": "human-audience"}, headers=headers)
            self.assertEqual(malformed_audience.status_code, 422)
            unavailable_issuer = client.post(root + "/certificate", json={
                "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n",
                "space_id": "job-space", "principal_id": "a" * 64}, headers=headers)
            self.assertEqual(unavailable_issuer.status_code, 503, unavailable_issuer.text)
            wrong_path = client.post(root.replace("/owner/1", "/owner/2") + "/validate", json=body, headers=headers)
            self.assertEqual(wrong_path.status_code, 404)
            transport.thumb = base64.urlsafe_b64encode(b"w" * 32).decode().rstrip("=")
            wrong_cert = client.post(root + "/validate", json=body, headers={**headers,
                "X-Verified-Peer-Thumbprint": node_thumb})
            self.assertEqual(wrong_cert.status_code, 401)
            unknown_node = client.post(root + "/bootstrap", json={}, headers={"X-SSL-Client-Cert": node_thumb})
            self.assertEqual(unknown_node.status_code, 401)
            transport.thumb = node_thumb
            with self.db.transaction() as session:
                session.get(models.Allocation, "managed-allocation").cpu_millicores = 2000
            changed = client.post(root + "/validate", json=body, headers=headers)
            self.assertEqual(changed.status_code, 401)

    def test_stream_revocation_invalidates_without_replaying_foreign_job_ids(self):
        job = self.create()
        self.auth.calls = 0
        self.auth.expire_after = 2
        def revoke(calls):
            if calls == 2:
                with self.db.transaction() as session:
                    session.delete(session.get(models.JobMember, (job["id"], "alice")))
        self.auth.on_auth = revoke
        response = self.client.get(BASE + "/events/stream", headers=self.headers())
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.text.count("event: invalidated"), 2)
        self.assertNotIn(job["id"], response.text)
        self.assertIn("event: session_expired", response.text)

    def external_fixture(self):
        from hf2l_jobs.participants import ApprovedExternalNode, ExternalParticipantService
        thumb = base64.urlsafe_b64encode(b"n" * 32).decode().rstrip("=")
        with self.db.transaction() as session:
            session.add(models.ParticipantBinding(id="dataset", project_id="project",
                participant_id="alice-data", node_id="external-node", dataset_label="Approved local data"))
        body = self.spec("External participant")
        body["participants"] = [
            {"participant_id": "alice-data", "dataset_binding": "dataset", "mode": "external"},
            {"participant_id": "bob-data", "dataset_binding": "data-bob", "mode": "external"}]
        created = self.client.post(BASE + "/jobs", json=body,
            headers=self.headers(key="external-create"))
        self.assertEqual(created.status_code, 202, created.text)
        job = created.json()
        source_root = Path(self.temp.name) / "private-sources"
        source_root.mkdir(mode=0o700)
        provisioner = SimpleNamespace(root=source_root)
        node = ApprovedExternalNode("external-node", thumb, {"dataset": {"kind": "synthetic"}})
        bob_thumb = base64.urlsafe_b64encode(b"b" * 32).decode().rstrip("=")
        bob_node = ApprovedExternalNode("external-node-bob", bob_thumb, {"data-bob": {"kind": "synthetic"}})
        service = ExternalParticipantService(self.manager, provisioner, SimpleNamespace(), [node, bob_node])
        app = create_app(self.manager, self.auth, participants=service, cursor_secret="c" * 32)
        return job, service, app, thumb, source_root

    def test_external_enrollment_has_job_acl_version_idempotency_and_fixed_node_approval(self):
        job, service, app, thumb, root = self.external_fixture()
        url = BASE + "/jobs/" + job["id"] + "/participants/alice-data"
        with TestClient(app, base_url="https://testserver") as client:
            headers = self.headers(key="enroll", version=1)
            enrolled = client.post(url + "/enroll", json={"node_id": "external-node"}, headers=headers)
            self.assertEqual(enrolled.status_code, 202, enrolled.text)
            replay = client.post(url + "/enroll", json={"node_id": "external-node"}, headers=headers)
            self.assertEqual(replay.json()["id"], enrolled.json()["id"])
            self.assertNotIn("token", enrolled.text)
            self.assertFalse(enrolled.json()["manager_allocation"])
            public = client.get(url + "/enrollment", headers=self.headers())
            self.assertEqual(public.status_code, 200)
            forbidden = client.get(url + "/enrollment", headers=self.headers("bob"))
            self.assertEqual(forbidden.status_code, 404)
            invalid = client.post(url + "/enroll", json={"node_id": "external-node", "dataset_path": "/etc"},
                headers=self.headers(key="unsafe", version=2))
            self.assertEqual(invalid.status_code, 422)
            self.assertNotIn("/etc", invalid.text)
            unapproved = client.post(url + "/enroll", json={"node_id": "other-node"},
                headers=self.headers(key="wrong-node", version=2))
            self.assertEqual(unapproved.status_code, 403)
        with self.db.transaction() as session:
            self.assertEqual(session.query(models.Allocation).count(), 0)

    def test_external_source_stream_is_pinned_private_and_fenced_while_stop_remains_allowed(self):
        job, service, app, thumb, root = self.external_fixture()
        enrollment = service.enroll("alice", job["id"], "alice-data", "external-node", 1, "enroll")
        payload = b"TRAINING_CODE = 'private pinned source'\n"
        source = root / job["id"] / "source"
        source.mkdir(parents=True, mode=0o700)
        (source / "plugin.py").write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        (source.parent / ".source.json").write_text(json.dumps({
            "source_id": "source", "commit": COMMIT, "manifest": {"plugin.py": digest}}))
        with self.db.transaction() as session:
            stored = session.get(models.Job, job["id"])
            stored.epoch, stored.state = 1, "RUNNING"
            attempt = session.query(models.Attempt).filter_by(job_id=job["id"], number=1).one()
            attempt.epoch, attempt.state = 1, "RUNNING"
            attempt_id = attempt.id
            resource = session.get(models.ProvisioningResource, enrollment["id"])
            resource.attempt_id = attempt.id
            resource.details_json = {**resource.details_json, "epoch": 1}
        actor = SimpleNamespace(id="node-principal", node_id="external-node", pool_id="external",
            job_id=job["id"], attempt_id=attempt_id, component_id=enrollment["component_id"],
            grant_id=enrollment["id"], epoch=1, certificate_thumbprint=thumb,
            scopes={"assignment", "stopped"})
        self.auth.authenticate_node = lambda authorization, peer: actor

        class ActualTLSState:
            def __init__(self, inner):
                self.inner = inner
            async def __call__(self, scope, receive, send):
                scope.setdefault("state", {})["verified_certificate_thumbprint"] = thumb
                await self.inner(scope, receive, send)

        route = "/internal/jobs/v1/participants/" + job["id"] + "/" + attempt_id + "/" + actor.component_id + "/1"
        with TestClient(ActualTLSState(app), base_url="https://testserver") as client:
            headers = {"Authorization": "Bearer external"}
            certificate = {"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n",
                           "space_id": "job-space", "principal_id": "a" * 64}
            unavailable = client.post(route + "/certificate", json=certificate, headers=headers)
            self.assertEqual(unavailable.status_code, 503, unavailable.text)
            self.assertEqual(unavailable.json()["error"]["code"], "execution_certificate_issuer_unavailable")
            unsafe_certificate = client.post(route + "/certificate",
                json={**certificate, "private_key_pem": "secret-never-accept"}, headers=headers)
            self.assertEqual(unsafe_certificate.status_code, 422)
            self.assertNotIn("secret-never-accept", unsafe_certificate.text)
            large_certificate = client.post(route + "/certificate",
                json={**certificate, "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n" + "x" * 16384 +
                    "\n-----END CERTIFICATE REQUEST-----\n"}, headers=headers)
            self.assertEqual(large_certificate.status_code, 422)
            response = client.get(route + "/source/plugin.py", headers=headers)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.content, payload)
            self.assertEqual(response.headers["x-content-sha256"], digest)
            self.assertTrue(response.headers["content-disposition"].startswith("attachment"))
            self.assertEqual(client.get(route + "/source/foreign.py", headers=headers).status_code, 404)
            with self.db.transaction() as session:
                session.get(models.Job, job["id"]).state = "CANCELLING"
            fenced = client.get(route + "/source/plugin.py", headers=headers)
            self.assertEqual(fenced.status_code, 404)
            false_stop = client.post(route + "/stopped", json={"termination_confirmed": False}, headers=headers)
            self.assertEqual(false_stop.status_code, 422)
            coerced_stop = client.post(route + "/stopped",
                json={"termination_confirmed": True, "never_started": "true"}, headers=headers)
            self.assertEqual(coerced_stop.status_code, 422)
            stopped = client.post(route + "/stopped",
                json={"termination_confirmed": True, "never_started": True}, headers=headers)
            self.assertEqual(stopped.status_code, 200, stopped.text)

    def test_readyz_checks_real_schema_and_reports_unavailable_without_details(self):
        response = self.client.get("/readyz")
        self.assertEqual(response.status_code, 200, response.text)
        broken = create_app(self.manager, self.auth, cursor_secret="c" * 32,
            readiness=lambda: (_ for _ in ()).throw(ValueError("secret=hidden")))
        with TestClient(broken, base_url="https://testserver") as client:
            response = client.get("/readyz")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("hidden", response.text)


from test_participant_build import BuildFixture


class ExternalRuntimeAPIAcceptance(BuildFixture):
    """Real participant/provisioner/collector ledger with HTTP identity boundary."""

    def api_client(self):
        actor = self.actor
        auth = SimpleNamespace(authenticate_node=lambda authorization, thumb: actor)
        app = create_app(self.manager, auth, participants=self.service, cursor_secret="c" * 32)
        class VerifiedTLS:
            def __init__(self, inner):
                self.inner = inner
            async def __call__(self, scope, receive, send):
                scope.setdefault("state", {})["verified_certificate_thumbprint"] = actor.certificate_thumbprint
                await self.inner(scope, receive, send)
        return TestClient(VerifiedTLS(app), base_url="https://testserver")

    def route(self):
        return "/internal/jobs/v1/participants/" + self.actor.job_id + "/" + self.actor.attempt_id + "/" + self.actor.component_id + "/" + str(self.actor.epoch)

    def test_verified_same_job_build_stream_and_revoked_or_foreign_bindings(self):
        route = self.route() + "/build-products/"
        with self.api_client() as client:
            headers = {"Authorization": "Bearer node"}
            response = client.get(route + self.filename, headers=headers)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.content, self.payload)
            self.assertEqual(response.headers["x-content-sha256"], self.artifacts[self.filename]["sha256"])
            self.assertEqual(response.headers["content-length"], str(len(self.payload)))
            self.assertTrue(response.headers["content-disposition"].startswith("attachment"))
            self.assertEqual(response.headers["x-content-type-options"], "nosniff")
            self.assertEqual(client.get(route + "unowned.whl", headers=headers).status_code, 404)
            self.assertEqual(client.get(route + "private.txt", headers=headers).status_code, 422)
            foreign = route.replace(self.actor.job_id, "foreign-job")
            self.assertEqual(client.get(foreign + self.filename, headers=headers).status_code, 404)
            (self.products / self.filename).write_bytes(b"changed")
            changed = client.get(route + self.filename, headers=headers)
            self.assertEqual(changed.status_code, 409)
            (self.products / self.filename).write_bytes(self.payload)
            self.set_state("CANCELLING")
            cancelled = client.get(route + self.filename, headers=headers)
            self.assertEqual(cancelled.status_code, 404)

    def test_external_log_receipts_are_contiguous_private_and_idempotent(self):
        from dataclasses import asdict
        from hf2l_jobs.executor import ExecutionIdentity
        identity = ExecutionIdentity(self.actor.job_id, self.actor.attempt_id, self.actor.component_id, self.actor.epoch)
        receipt = {"identity": asdict(identity), "source_id": identity.key, "offset": 0,
                   "next_offset": 5, "content": "ready", "complete": False, "truncated": False}
        with self.api_client() as client:
            headers = {"Authorization": "Bearer node"}
            root = self.route() + "/logs"
            first = client.post(root, json=receipt, headers=headers)
            self.assertEqual(first.status_code, 200, first.text)
            self.assertTrue(first.json()["accepted"])
            replay = client.post(root, json=receipt, headers=headers)
            self.assertEqual(replay.status_code, 200, replay.text)
            self.assertEqual(replay.json()["next_offset"], 5)
            malformed = client.post(root, json={**receipt, "next_offset": 6}, headers=headers)
            self.assertEqual(malformed.status_code, 422)
            too_big = client.post(root, json={**receipt, "content": "x" * 65537,
                "next_offset": 65537}, headers=headers)
            self.assertEqual(too_big.status_code, 422)
            boolean_cursor = client.post(root, json={**receipt, "offset": False}, headers=headers)
            self.assertEqual(boolean_cursor.status_code, 422)
            gap = client.post(root, json={**receipt, "offset": 7, "next_offset": 12}, headers=headers)
            self.assertEqual(gap.status_code, 409)
        with self.database.transaction(immediate=False) as session:
            chunks = list(session.query(models.LogChunk).filter_by(job_id=self.actor.job_id))
            self.assertEqual(len(chunks), 1)
            self.assertEqual(chunks[0].data, "ready")


if __name__ == "__main__":
    unittest.main()
