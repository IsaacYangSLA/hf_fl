"""Independent manager API tests using real signed OIDC over actual TLS.

A passing test here qualifies control-plane behavior only. Production sandbox,
managed transfer isolation and actual FL progress have separate live gates.
"""
from __future__ import annotations

from contextlib import ExitStack
from datetime import timedelta
import json
import secrets
import tempfile
import time
import unittest
from urllib.parse import urlsplit

from fastapi.testclient import TestClient
import httpx
from sqlalchemy import select

from support_system import TLSOIDCProvider, isolated_database, live_api


class ManagerHTTPIntegrationTests(unittest.TestCase):
    def setUp(self):
        from hf2l_jobs.api import create_app
        from hf2l_jobs.application import Manager
        from hf2l_jobs.auth import AuthService, principal_id
        from hf2l_jobs.config import OIDCSettings, Settings
        from hf2l_jobs.database import create_database
        from hf2l_jobs import models
        from hf2l_jobs.oidc import OIDCProvider

        self.models = models
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = self.stack.enter_context(tempfile.TemporaryDirectory(prefix="jobs-system-"))
        self.identity = TLSOIDCProvider(self.directory)
        self.stack.callback(self.identity.close)
        database_url = self.stack.enter_context(isolated_database(self.directory))
        self.database = create_database(database_url)
        self.stack.callback(self.database.close)
        self.settings = Settings(database_url=database_url, cursor_secret="system-cursor-" + "a" * 32,
                    session_secret="system-session-" + "b" * 32,
                    oidc=OIDCSettings(issuer=self.identity.issuer, client_id="integration-client",
                    redirect_uri="https://testserver/auth/callback", audience="hf2l-jobs"))
        self.auth = AuthService(self.database.session_factory, self.settings,
                               oidc_provider=OIDCProvider(self.settings.oidc, self.identity.client))
        self.manager = Manager(self.database, cursor_secret=self.settings.cursor_secret)
        self.alice = principal_id(self.identity.issuer, "alice")
        self.bob = principal_id(self.identity.issuer, "bob")
        self.operator = principal_id(self.identity.issuer, "platform-operator")
        self.commit = "a" * 40
        self.image = "sha256:" + "b" * 64
        with self.database.transaction() as session:
            session.add(models.Project(id="project", name="System integration project"))
            session.flush()
            session.add_all([
                models.ProjectMember(project_id="project", principal_id=self.alice, role="submitter"),
                models.ProjectMember(project_id="project", principal_id=self.bob, role="submitter"),
                models.ApprovedSource(id="source", project_id="project", name="Approved exact commit",
                    url="https://github.com/IsaacYangSLA/hf_fl.git", allowed_commits=[self.commit],
                    allowed_hosts=["github.com"]),
                models.RuntimeImage(id="runtime", project_id="project", digest=self.image),
                models.ParticipantBinding(id="dataset-alice",project_id="project",participant_id="alice",
                    node_id="node",dataset_label="Approved API fixture Alice"),
                models.ParticipantBinding(id="dataset-bob",project_id="project",participant_id="bob",
                    node_id="node",dataset_label="Approved API fixture Bob"),
                models.Pool(id="cpu-pool", name="Explicit allocatable CPU", node_id="node",
                    cpu_millicores=2000, memory_bytes=2**30, disk_bytes=2**30,
                    healthy=True, sandbox_profiles=["runsc-cpu-v1"]),
            ])
        self.app = create_app(self.manager, self.auth, cursor_secret=self.settings.cursor_secret,
                              allow_local_http=False, sse_poll_seconds=.05)
        self.client = self.stack.enter_context(TestClient(self.app, base_url="https://testserver",
                                                       raise_server_exceptions=False, follow_redirects=False))

    def spec(self, name="Independent job", **overrides):
        result = {"project_id": "project", "name": name, "source_id": "source",
                  "source_commit": self.commit, "runtime_image": "runtime", "plugin": "examples.lenet:Plugin",
                  "options": {"seed": 7}, "participants": [
                    {"participant_id":"alice","component_id":"client-alice","mode":"managed","dataset_binding":"dataset-alice"},
                    {"participant_id":"bob","component_id":"client-bob","mode":"managed","dataset_binding":"dataset-bob"}],
                  "components": [
                    {"component_id": "owner", "role": "owner", "resources": {"pool_id": "cpu-pool",
                     "cpu_millicores": 1000, "memory_bytes": 64 * 1024**2, "disk_bytes": 64 * 1024**2}},
                    *[{"component_id":"client-"+participant,"role":"participant","participant_id":participant,
                       "resources":{"pool_id":"cpu-pool","cpu_millicores":250,
                                    "memory_bytes":64*1024**2,"disk_bytes":64*1024**2}}
                      for participant in ("alice","bob")]],
                  "target_round": 2, "max_duration_seconds": 300}
        result.update(overrides)
        return result

    def test_actual_create_rejects_default_quorum_without_durable_rows(self):
        for count in (0,1):
            spec=self.spec()
            spec["participants"]=spec["participants"][:count]
            allowed={"owner",*[p["component_id"] for p in spec["participants"]]}
            spec["components"]=[c for c in spec["components"] if c["component_id"] in allowed]
            response=self.request("POST","/api/jobs/v1/jobs",json=spec)
            self.assertEqual(response.status_code,422,response.text)
        self.assertEqual(self.request("GET","/api/jobs/v1/jobs").json()["total"],0)
        with self.database.transaction(immediate=False) as session:
            for model in (self.models.Job,self.models.Attempt,self.models.Allocation,self.models.ProvisioningResource):
                self.assertEqual(list(session.scalars(select(model))),[])

    def request(self, method, path, subject="alice", *, key=None, headers=None, **kwargs):
        merged = {"Authorization": "Bearer " + self.identity.access_token(subject)}
        if method.upper() in {"POST", "PUT", "DELETE"}:
            merged["Idempotency-Key"] = key or secrets.token_hex(16)
        merged.update(headers or {})
        return self.client.request(method, path, headers=merged, **kwargs)

    def create(self, name="Independent job", subject="alice", key=None, **overrides):
        response = self.request("POST", "/api/jobs/v1/jobs", subject, key=key,
                                json=self.spec(name, **overrides))
        self.assertEqual(response.status_code, 202, response.text)
        return response.json()

    def login(self, subject="alice"):
        self.identity.subject = subject
        response = self.client.get("/auth/login")
        self.assertEqual(response.status_code, 303, response.text)
        self.assertIn("Secure", response.headers["set-cookie"])
        self.assertIn("HttpOnly", response.headers["set-cookie"])
        self.assertIn("SameSite=lax", response.headers["set-cookie"])
        target = self.identity.authorize(response.headers["location"])
        parsed = urlsplit(target)
        callback = self.client.get(parsed.path + "?" + parsed.query)
        self.assertEqual(callback.status_code, 303, callback.text)
        self.assertIn("Secure", callback.headers["set-cookie"])
        self.assertNotIn("access_token", callback.headers["set-cookie"])
        session = self.client.get("/api/jobs/v1/session")
        self.assertEqual(session.status_code, 200, session.text)
        return session.json(), parsed.path + "?" + parsed.query

    def test_real_tls_oidc_pkce_session_csrf_and_one_use_callback(self):
        session, callback = self.login()
        self.assertEqual(session["principal"]["principal_id"], self.alice)
        self.assertTrue(session["csrf_token"])
        denied = self.client.post("/api/jobs/v1/jobs", json=self.spec(), headers={"Idempotency-Key": "session-create"})
        self.assertEqual(denied.status_code, 403, denied.text)
        accepted = self.client.post("/api/jobs/v1/jobs", json=self.spec(), headers={
            "Idempotency-Key": "session-create", "X-CSRF-Token": session["csrf_token"], "Origin": "https://testserver"})
        self.assertEqual(accepted.status_code, 202, accepted.text)
        repeated = self.client.get(callback)
        self.assertEqual(repeated.status_code, 401, repeated.text)
        logout = self.client.post("/auth/logout", headers={"X-CSRF-Token": session["csrf_token"],
                                                          "Origin": "https://testserver"})
        self.assertEqual(logout.status_code, 200, logout.text)
        self.assertEqual(self.client.get("/api/jobs/v1/jobs").status_code, 401)
        self.assertIn(("POST", "/token"), self.identity.requests)
        self.assertIn(("GET", "/jwks"), self.identity.requests)

    def test_acl_before_queue_history_search_counts_and_foreign_detail(self):
        alice = self.create("Alice confidential title")
        bob = self.create("Bob confidential title", "bob")
        result = self.request("GET", "/api/jobs/v1/jobs?view=queued").json()
        self.assertEqual([item["id"] for item in result["items"]], [alice["id"]])
        self.assertNotIn(bob["id"], json.dumps(result))
        self.assertNotIn("Bob confidential", json.dumps(result))
        self.assertEqual(result["counts"]["queued"], 1)
        for suffix in ("", "/events", "/attempts", "/logs", "/artifacts", "/members"):
            response = self.request("GET", "/api/jobs/v1/jobs/" + bob["id"] + suffix)
            self.assertEqual(response.status_code, 404, response.text)
        cancelled = self.request("POST", "/api/jobs/v1/jobs/" + bob["id"] + "/cancel",
                                headers={"If-Match": '"1"'})
        self.assertEqual(cancelled.status_code, 404, cancelled.text)
        with self.database.transaction() as session:
            for identity in (alice["id"], bob["id"]):
                job = session.get(self.models.Job, identity)
                job.state = "SUCCEEDED"
                job.current_round = job.target_round
                job.terminated_at = self.manager.now()
        history = self.request("GET", "/api/jobs/v1/jobs?view=history").json()
        self.assertEqual([item["id"] for item in history["items"]], [alice["id"]])
        self.assertEqual(history["counts"]["history"], 1)
        search = self.request("GET", "/api/jobs/v1/jobs?view=history&search=Bob")
        self.assertEqual(search.status_code, 200, search.text)
        self.assertEqual(search.json()["items"], [])

    def test_idempotent_creation_and_versions_are_durable(self):
        body = self.spec("Replay safely")
        first = self.request("POST", "/api/jobs/v1/jobs", key="replay", json=body)
        replay = self.request("POST", "/api/jobs/v1/jobs", key="replay", json=body)
        self.assertEqual(first.status_code, 202, first.text)
        self.assertEqual(replay.status_code, 202, replay.text)
        self.assertEqual(first.json()["id"], replay.json()["id"])
        different = self.request("POST", "/api/jobs/v1/jobs", key="replay", json=self.spec("Different"))
        self.assertEqual(different.status_code, 409, different.text)
        bob = self.create("Bob different principal same key", "bob", key="replay")
        self.assertNotEqual(bob["id"], first.json()["id"])
        job_id = first.json()["id"]
        missing = self.request("POST", "/api/jobs/v1/jobs/" + job_id + "/cancel")
        self.assertEqual(missing.status_code, 428, missing.text)
        cancelled = self.request("POST", "/api/jobs/v1/jobs/" + job_id + "/cancel", key="cancel",
                                 headers={"If-Match": '"1"'})
        self.assertEqual(cancelled.status_code, 202, cancelled.text)
        stale = self.request("POST", "/api/jobs/v1/jobs/" + job_id + "/cancel", key="stale",
                             headers={"If-Match": '"1"'})
        self.assertEqual(stale.status_code, 409, stale.text)
        repeated = self.request("POST", "/api/jobs/v1/jobs/" + job_id + "/cancel", key="cancel",
                                headers={"If-Match": '"1"'})
        self.assertEqual(repeated.status_code, 202, repeated.text)
        with self.database.transaction() as session:
            rows = list(session.scalars(select(self.models.Outbox).where(self.models.Outbox.job_id == job_id)))
            self.assertEqual(len(rows), 1)

    def test_membership_is_current_and_last_administrator_is_preserved(self):
        job = self.create()
        path = "/api/jobs/v1/jobs/" + job["id"] + "/members/"
        protected = self.request("DELETE", path + self.alice, headers={"If-Match": '"1"'})
        self.assertEqual(protected.status_code, 409, protected.text)
        grant = self.request("PUT", path + self.bob, json={"role": "reader"}, headers={"If-Match": '"1"'})
        self.assertEqual(grant.status_code, 200, grant.text)
        self.assertEqual(self.request("GET", "/api/jobs/v1/jobs/" + job["id"], "bob").status_code, 200)
        read_only = self.request("POST", "/api/jobs/v1/jobs/" + job["id"] + "/cancel", "bob",
                                headers={"If-Match": '"2"'})
        self.assertEqual(read_only.status_code, 403, read_only.text)
        revoke = self.request("DELETE", path + self.bob, headers={"If-Match": '"2"'})
        self.assertEqual(revoke.status_code, 200, revoke.text)
        self.assertEqual(self.request("GET", "/api/jobs/v1/jobs/" + job["id"], "bob").status_code, 404)
        self.assertEqual(self.request("GET", "/api/jobs/v1/jobs", "bob").json()["total"], 0)

    def test_principal_and_filter_bound_pagination_rechecks_acl(self):
        alice_first = self.create("Alice first")
        self.create("Bob foreign", "bob")
        alice_second = self.create("Alice second")
        first = self.request("GET", "/api/jobs/v1/jobs?limit=1&view=queued")
        self.assertEqual(first.status_code, 200, first.text)
        cursor = first.json()["next_cursor"]
        self.assertTrue(cursor)
        foreign = self.request("GET", "/api/jobs/v1/jobs?limit=1&view=queued&cursor=" + cursor, "bob")
        self.assertEqual(foreign.status_code, 422, foreign.text)
        changed = self.request("GET", "/api/jobs/v1/jobs?limit=1&view=history&cursor=" + cursor)
        self.assertEqual(changed.status_code, 422, changed.text)
        first_id = first.json()["items"][0]["id"]
        removed_id = next(value for value in (alice_first["id"], alice_second["id"]) if value != first_id)
        with self.database.transaction() as session:
            session.delete(session.get(self.models.JobMember, (removed_id, self.alice)))
        page = self.request("GET", "/api/jobs/v1/jobs?limit=1&view=queued&cursor=" + cursor)
        self.assertEqual(page.status_code, 200, page.text)
        self.assertNotIn(removed_id, json.dumps(page.json()))
        self.assertEqual(page.json()["total"], 1)
        self.assertEqual(page.json()["items"], [])

    def test_invalid_inputs_are_rejected_without_echoing_secrets(self):
        for overrides in (
            {"options": {"api_token": "never-echo-this-secret"}},
            {"options": {"host_path": "/another/job"}},
            {"target_round": True},
            {"source_commit": "main"},
            {"source_id": "../foreign"},
            {"runtime_image": "unknown-runtime"},
        ):
            response = self.request("POST", "/api/jobs/v1/jobs", json=self.spec(**overrides))
            self.assertEqual(response.status_code, 422, response.text)
            self.assertNotIn("never-echo-this-secret", response.text)
            self.assertNotIn("/another/job", response.text)
        self.assertEqual(self.request("GET", "/api/jobs/v1/jobs").json()["total"], 0)

    def test_actual_provider_revocation_and_wrong_audience_fail_closed(self):
        created = self.create()
        wrong = self.identity.access_token("alice", aud="foreign-service")
        response = self.client.get("/api/jobs/v1/jobs/" + created["id"],
                                   headers={"Authorization": "Bearer " + wrong})
        self.assertEqual(response.status_code, 401, response.text)
        malformed = self.client.get("/api/jobs/v1/jobs", headers={"Authorization": "Bearer malformed"})
        self.assertEqual(malformed.status_code, 401, malformed.text)
        self.identity.disabled_subjects.add("alice")
        response = self.request("GET", "/api/jobs/v1/jobs/" + created["id"])
        self.assertEqual(response.status_code, 401, response.text)

    def test_session_online_revalidation_and_absolute_expiry(self):
        session, _ = self.login()
        with self.database.transaction() as connection:
            row = connection.scalar(select(self.models.AuthSession).where(self.models.AuthSession.principal_id == self.alice))
            row.checked_at = self.manager.now() - timedelta(minutes=16)
        self.identity.disabled_subjects.add("alice")
        response = self.client.get("/api/jobs/v1/jobs")
        self.assertEqual(response.status_code, 401, response.text)
        with self.database.transaction() as connection:
            row = connection.scalar(select(self.models.AuthSession).where(self.models.AuthSession.principal_id == self.alice))
            self.assertIsNotNone(row.revoked_at)
        self.client.cookies.clear()
        self.identity.disabled_subjects.clear()
        self.login()
        with self.database.transaction() as connection:
            rows = list(connection.scalars(select(self.models.AuthSession).where(
                self.models.AuthSession.principal_id == self.alice, self.models.AuthSession.revoked_at.is_(None))))
            self.assertEqual(len(rows), 1)
            rows[0].absolute_expires_at = self.manager.now() - timedelta(seconds=1)
        self.assertEqual(self.client.get("/api/jobs/v1/jobs").status_code, 401)

    def test_platform_role_does_not_grant_job_contents(self):
        from dataclasses import replace
        from hf2l_jobs.auth import AuthService
        self.auth.settings = replace(self.settings, platform_operator_ids=(self.operator,))
        job = self.create()
        principal = self.auth.authenticate_request(authorization="Bearer " + self.identity.access_token("platform-operator"))
        self.assertTrue(principal.platform_operator)
        response = self.request("GET", "/api/jobs/v1/jobs/" + job["id"], "platform-operator")
        self.assertEqual(response.status_code, 404, response.text)
        self.assertEqual(self.request("GET", "/api/jobs/v1/jobs", "platform-operator").json()["total"], 0)

    def test_dashboard_security_headers_and_schema_readiness(self):
        response = self.client.get("/readyz")
        self.assertEqual(response.status_code, 200, response.text)
        for path in ("/dashboard/", "/api/jobs/v1/jobs", "/not-found"):
            response = self.client.get(path)
            self.assertIn("default-src 'self'", response.headers["content-security-policy"])
            self.assertEqual(response.headers["x-content-type-options"], "nosniff")
            self.assertEqual(response.headers["cache-control"], "no-store")
            self.assertNotIn("unsafe-inline", response.headers["content-security-policy"])
            self.assertTrue(response.headers["x-request-id"])

    def test_real_https_sse_rechecks_sessions_and_revocation(self):
        token = self.identity.access_token("alice")
        job = self.create()
        with live_api(self.app, self.identity.cert_path, self.identity.tls_key_path) as base:
            with httpx.Client(verify=self.identity.context, trust_env=False, timeout=5) as client:
                with client.stream("GET", base + "/api/jobs/v1/events/stream",
                                   headers={"Authorization": "Bearer " + token}) as stream:
                    self.assertEqual(stream.status_code, 200)
                    lines = stream.iter_lines()
                    event = []
                    for line in lines:
                        if not line and event:
                            break
                        event.append(line)
                    self.assertTrue(any(line.startswith("id:") for line in event), event)
                    cursor = next(line[3:].strip() for line in event if line.startswith("id:"))
                    self.identity.disabled_subjects.add("alice")
                    closed = []
                    for line in lines:
                        closed.append(line)
                        if "session_expired" in line:
                            break
                    self.assertTrue(any("session_expired" in line for line in closed), closed)
                bad = client.get(base + "/api/jobs/v1/events/stream", headers={
                    "Authorization": "Bearer " + self.identity.access_token("bob"),
                    "Last-Event-ID": cursor})
                self.assertEqual(bad.status_code, 400, bad.text)


if __name__ == "__main__":
    unittest.main()
