"""Live PostgreSQL and S3 HTTP proof of managed checkpoint storage bounds.

Both EXCHANGE_TEST_DATABASE_URL and EXCHANGE_TEST_S3_ENDPOINT are required.
Every test owns its PostgreSQL schemas, versioned bucket, and synthetic keys.
No model is deserialized and no existing storage namespace is reset.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import importlib.util
import os
from pathlib import Path
import time
import unittest
from uuid import uuid4

_LIVE = bool(os.environ.get("EXCHANGE_TEST_DATABASE_URL") and os.environ.get("EXCHANGE_TEST_S3_ENDPOINT"))
if _LIVE:
    support_path = Path(__file__).resolve().parents[2] / "exchange" / "tests" / "support.py"
    module_spec = importlib.util.spec_from_file_location("hf2l_blob_budget_exchange_support", support_path)
    support = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(support)
    ExchangeTestCase = support.ExchangeTestCase
else:
    ExchangeTestCase = unittest.TestCase


@unittest.skipUnless(_LIVE, "Live PostgreSQL/S3 checkpoint-budget fixtures are not configured")
class BlobBudgetExchangeTests(ExchangeTestCase):
    def setUp(self):
        super().setUp()
        from fastapi.testclient import TestClient
        from sqlalchemy import create_engine, text
        from sqlalchemy.engine import make_url
        from hf2l_exchange.api import create_app
        from hf2l_exchange.auth import principal_id
        from hf2l_jobs.database import create_database
        from hf2l_jobs.models import Pool, Project
        from hf2l_jobs.resources import ResourceLedger
        from hf2l_jobs.retention import RetentionService

        # The normal RSA issuer remains unchanged. The second fixed issuer only
        # exists on this private trusted-backend fixture, using synthetic keys.
        self.workload_issuer = "https://workload-budget.example.test"
        self.backend_secret = "synthetic-budget-backend-key-32-bytes"
        auth = replace(self.settings.auth, workload_issuer=self.workload_issuer,
            workload_public_key=self.public_key, trusted_backend_secret=self.backend_secret,
            provisioning_principal_ids=(principal_id(self.issuer, "owner"),))
        self.settings = replace(self.settings, auth=auth,
            storage=replace(self.settings.storage, grant_seconds=1))
        self.service.settings = self.settings
        self.transfers.settings = self.settings
        self.client = TestClient(create_app(self.settings, service=self.service,
            transfers=self.transfers, managed_ingress=True))
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        self.schema = "jm_blob_budget_" + uuid4().hex
        url = make_url(os.environ["EXCHANGE_TEST_DATABASE_URL"])
        self.admin = create_engine(url)
        self.addCleanup(self.admin.dispose)
        with self.admin.begin() as connection:
            connection.execute(text('CREATE SCHEMA "' + self.schema + '"'))
        def cleanup_schema():
            with self.admin.begin() as connection:
                connection.execute(text('DROP SCHEMA IF EXISTS "' + self.schema + '" CASCADE'))
        self.addCleanup(cleanup_schema)
        isolated = url.update_query_dict({"options": "-csearch_path=" + self.schema + " -clock_timeout=10000"})
        self.database = create_database(isolated.render_as_string(hide_password=False), isolation_level="READ COMMITTED")
        self.addCleanup(self.database.close)
        self.ledger = ResourceLedger(self.database)
        self.retention = RetentionService(self.database)
        with self.database.transaction() as session:
            session.add(Project(id="project", name="Budget proof", quotas_json={"disk_bytes": 1000, "retained_bytes": 1000}))
            session.add(Pool(id="compute", name="Compute", node_id="fixture-node", cpu_millicores=1000,
                memory_bytes=1000, disk_bytes=1000, sandbox_profiles=["runsc-cpu-v1"], healthy=True))
            session.add(Pool(id="objects", name="Approved S3 budget", node_id="s3-fixture", cpu_millicores=0,
                memory_bytes=0, disk_bytes=140, healthy=True, details_json={"object_store": True}))

    def request(self, method, path, subject="owner", *, key=None, headers=None, **kwargs):
        if not getattr(self, "backend_secret", None):
            return super().request(method, path, subject, key=key, headers=headers, **kwargs)
        from hf2l_exchange.auth import backend_assertion_headers
        auth = self.auth(subject)
        auth.update(headers or {})
        if method.lower() in {"post", "put"}:
            auth.update(self.operation_key(key))
        auth.update(backend_assertion_headers(self.backend_secret, method, path,
            auth["Authorization"], "a" * 43))
        return self.client.request(method, path, headers=auth, **kwargs)

    def job(self, jid):
        from test_blob_budget import spec
        from hf2l_jobs.domain import utcnow
        from hf2l_jobs.models import Attempt, Job
        specification = spec()
        with self.database.transaction() as session:
            job = Job(id=jid, project_id="project", creator_id="human", name="Budget job",
                spec_json=specification.to_dict(), spec_hash=specification.digest, state="QUEUED",
                target_round=2, current_attempt=1, attempt_count=1, created_at=utcnow())
            session.add(job)
            session.flush()
            session.add(Attempt(id="attempt-" + jid, job_id=jid, number=1, epoch=1))
        return job

    def owned_space(self, job):
        from hf2l_jobs.blob_budget import KIND, bind_blob_space, plan_blob_budget, require_blob_budget
        plan = plan_blob_budget(job, "objects", self.ledger.resources(job.id))
        rid = self.ledger.own(job_id=job.id, attempt_id="attempt-" + job.id,
            component_id=plan["component_id"], kind=KIND, external_id=plan["external_id"],
            details=plan["details"], retained=True)
        self.retention.reserve_resource(rid, job.id, plan["max_bytes"])
        prepaid = require_blob_budget(self.database, job)
        space = self.new_space("hf2l-" + job.id, quota_bytes=prepaid["quota_bytes"],
            principal_quota_bytes=prepaid["principal_quota_bytes"])
        self.ledger.own(job_id=job.id, attempt_id="attempt-" + job.id, component_id="leader",
            kind="exchange_space", external_id=space["id"], details={"job_id": job.id}, retained=True)
        observed = self.request("GET", "/v2/spaces/" + space["id"])
        self.assertEqual(observed.status_code, 200, observed.text)
        bind_blob_space(self.database, job, space["id"], space_policy=observed.json())
        response = self.request("PUT", "/v2/spaces/" + space["id"] + "/managed", json={"job_id": job.id})
        self.assertEqual(response.status_code, 200, response.text)
        revision = self.register_type("document", space=space["id"])
        return space, revision

    def workload(self, job, space, name):
        import jwt
        from hf2l_exchange.auth import Authenticator, backend_assertion_headers, principal_id
        subject = job.id + "-" + name
        pid = principal_id(self.workload_issuer, subject)
        prefix = "/v2/spaces/" + space["id"]
        response = self.request("PUT", prefix + "/members/" + pid,
            json={"subject": subject, "roles": ["reader", "contributor"], "bindings": {}})
        self.assertEqual(response.status_code, 200, response.text)
        response = self.request("POST", prefix + "/workload-grants", json={"subject": subject,
            "job_id": job.id, "attempt_id": "attempt-" + job.id, "component_id": "worker-" + name,
            "epoch": 1, "certificate_thumbprint": "a" * 43, "roles": ["reader", "contributor"],
            "bindings": {}, "expires_at": time.time() + 600})
        self.assertEqual(response.status_code, 201, response.text)
        grant = response.json()
        now = int(time.time())
        claims = {"iss": self.workload_issuer, "aud": "exchange-workload", "sub": subject,
            "iat": now, "exp": now + 120, "scope": "exchange", "jti": grant["grant_id"],
            "space_id": space["id"], "job_id": job.id, "attempt_id": "attempt-" + job.id,
            "component_id": "worker-" + name, "epoch": 1, "cnf": {"x5t#S256": "a" * 43}}
        authorization = "Bearer " + jwt.encode(claims, self.private_key, algorithm="RS256", headers={"typ": "at+jwt"})
        principal = Authenticator(self.settings.auth).authenticate(authorization, managed=True,
            certificate_thumbprint="a" * 43)
        def request(method, route, **kwargs):
            headers = {"Authorization": authorization, **self.operation_key(),
                **backend_assertion_headers(self.backend_secret, method, route, authorization, "a" * 43)}
            return self.client.request(method, route, headers=headers, **kwargs)
        return principal, request

    def create_blob(self, requester, space, revision, payload):
        return requester("POST", "/v2/spaces/" + space["id"] + "/records", json={
            "kind": "document", "schema_revision_id": revision["id"], "metadata": {},
            "attachments": [{"path": "weights.bin", "size": len(payload),
                             "sha256": hashlib.sha256(payload).hexdigest()}]})

    def held(self, expected):
        from hf2l_jobs.models import Project
        from hf2l_jobs.retention import RetentionService
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(session.get(Project, "project").retained_bytes, expected)
            self.assertEqual(RetentionService.pool_used_bytes(session, "objects"), expected)

    def terminal(self, job):
        from hf2l_jobs.models import Job
        with self.database.transaction() as session:
            session.get(Job, job.id).state = "SUCCEEDED"
        job.state = "SUCCEEDED"

    def test_pending_and_committed_managed_blobs_obey_prepaid_cap_and_neighbor_isolation(self):
        import httpx
        from sqlalchemy import select
        from hf2l_exchange.models import Blob
        from hf2l_exchange.worker import tick
        from hf2l_jobs.blob_budget import confirm_blob_cleanup, require_blob_budget
        job = self.job("job")
        space, revision = self.owned_space(job)
        alpha, alpha_request = self.workload(job, space, "alpha")
        _, beta_request = self.workload(job, space, "beta")
        _, gamma_request = self.workload(job, space, "gamma")
        payload = b"a" * 30
        response = self.create_blob(alpha_request, space, revision, payload)
        self.assertEqual(response.status_code, 201, response.text)
        record = response.json()
        denied = self.create_blob(alpha_request, space, revision, b"x")
        self.assertEqual((denied.status_code, self.code(denied)), (409, "principal_blob_quota_exceeded"))
        self.assertEqual(self.create_blob(beta_request, space, revision, b"b" * 30).status_code, 201)
        denied = self.create_blob(gamma_request, space, revision, b"c" * 11)
        self.assertEqual((denied.status_code, self.code(denied)), (409, "blob_quota_exceeded"))
        self.assertEqual(self.create_blob(gamma_request, space, revision, b"c" * 10).status_code, 201)
        prefix = "/v2/spaces/" + space["id"]
        observed = self.request("GET", prefix).json()
        self.assertEqual((observed["allocated"], observed["quota_bytes"]), (70, 70))
        self.held(70)

        attachment = record["attachments"][0]
        route = prefix + "/records/" + record["id"] + "/attachments/" + attachment["id"]
        initiated = alpha_request("POST", route + "/upload")
        self.assertEqual(initiated.status_code, 200, initiated.text)
        # The private fixture is the trusted gateway side. Workloads receive only
        # structured transfer descriptors; actual signed URL stays outside them.
        public_grants = alpha_request("POST", route + "/grants", json={"numbers": [1]})
        self.assertEqual(public_grants.status_code, 200, public_grants.text)
        self.assertNotIn("url", public_grants.json()["grants"][0])
        grants = self.transfers.grants(space["id"], record["id"], attachment["id"], alpha, [1])
        for grant in grants["grants"]:
            uploaded = httpx.put(grant["url"], headers=grant["headers"], content=payload, timeout=10)
            self.assertEqual(uploaded.status_code, 200)
        completed = alpha_request("POST", route + "/complete")
        self.assertEqual(completed.status_code, 202, completed.text)
        for _ in range(3):
            tick(self.transfers)
        response = alpha_request("POST", prefix + "/records/" + record["id"] + "/publish")
        self.assertEqual(response.status_code, 200, response.text)
        with self.service.sessions() as session:
            blob = session.scalar(select(Blob).where(Blob.id == attachment["id"]))
            object_key = blob.object_key
            self.assertEqual((blob.state, blob.verified_size), ("verified", 30))
        denied = self.create_blob(gamma_request, space, revision, b"x")
        self.assertEqual((denied.status_code, self.code(denied)), (409, "blob_quota_exceeded"))

        neighbor = self.job("neighbor")
        neighbor_space, neighbor_revision = self.owned_space(neighbor)
        _, neighbor_request = self.workload(neighbor, neighbor_space, "alpha")
        self.assertEqual(self.create_blob(neighbor_request, neighbor_space, neighbor_revision, b"n" * 30).status_code, 201)
        foreign = alpha_request("GET", "/v2/spaces/" + neighbor_space["id"])
        self.assertEqual(foreign.status_code, 404)
        self.held(140)
        # Legacy generic spaces continue to accept their ordinary RSA authority.
        ordinary = self.ready(subject="alice", metadata={"legacy": "still works"})
        self.assertEqual(ordinary["state"], "published")

        revoked = self.request("POST", prefix + "/workload-grants/revoke", json={"attempt_id": "attempt-job"})
        self.assertEqual(revoked.status_code, 200, revoked.text)
        retired = self.request("POST", prefix + "/managed/retire", json={"job_id": "job"})
        self.assertEqual(retired.status_code, 200, retired.text)
        self.terminal(job)
        proof = self.request("GET", prefix + "/managed").json()
        self.assertTrue(proof["cleanup_pending"])
        self.assertFalse(confirm_blob_cleanup(self.database, job, space["id"], proof))
        self.held(140)
        self.assertTrue(self.s3.list_object_versions(Bucket=self.bucket, Prefix=object_key).get("Versions"))
        for _ in range(40):
            tick(self.transfers)
            proof = self.request("GET", prefix + "/managed").json()
            if proof["cleanup_pending"] is False:
                break
            time.sleep(.1)
        self.assertFalse(proof["cleanup_pending"])
        self.assertFalse(self.s3.list_object_versions(Bucket=self.bucket, Prefix=object_key).get("Versions"))
        self.assertTrue(confirm_blob_cleanup(self.database, job, space["id"], proof))
        self.assertTrue(confirm_blob_cleanup(self.database, job, space["id"], proof))
        self.held(70)
        self.assertEqual(require_blob_budget(self.database, neighbor)["space_id"], neighbor_space["id"])
        self.assertEqual(self.request("GET", prefix + "/managed").json()["status"], "retired")

    def test_postgres_object_capacity_blocks_next_gang_until_confirmed_deletion(self):
        from sqlalchemy import select
        from hf2l_jobs.blob_budget import confirm_blob_cleanup, plan_blob_budget
        from hf2l_jobs.domain import utcnow
        from hf2l_jobs.models import Allocation, Job, Pool
        from hf2l_jobs.scheduler import Scheduler
        first, second = self.job("first"), self.job("second")
        with self.database.transaction() as session:
            session.get(Pool, "objects").disk_bytes = 100
        planner = lambda job: [plan_blob_budget(job, "objects", self.ledger.resources(job.id))]
        scheduler = Scheduler(self.database, admission_storage=planner)
        self.assertEqual([admission.job_id for admission in scheduler.schedule(limit=2)], [first.id])
        space, _ = self.owned_space(first)
        with self.database.transaction() as session:
            session.get(Job, first.id).state = "SUCCEEDED"
            for allocation in session.scalars(select(Allocation).where(Allocation.job_id == first.id)):
                allocation.state = "RELEASED"
                allocation.released_at = utcnow()
                allocation.termination_confirmed = True
                allocation.details_json = {**allocation.details_json, "storage_deleted": True}
        first.state = "SUCCEEDED"
        self.assertEqual(scheduler.schedule(limit=2), [])
        self.held(70)
        prefix = "/v2/spaces/" + space["id"]
        retired = self.request("POST", prefix + "/managed/retire", json={"job_id": first.id})
        self.assertEqual(retired.status_code, 200, retired.text)
        proof = self.request("GET", prefix + "/managed").json()
        self.assertFalse(proof["cleanup_pending"])
        self.assertTrue(confirm_blob_cleanup(self.database, first, space["id"], proof))
        self.assertEqual([admission.job_id for admission in scheduler.schedule(limit=2)], [second.id])
        self.held(70)


if __name__ == "__main__":
    unittest.main()
