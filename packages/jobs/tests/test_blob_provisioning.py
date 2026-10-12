"""Real SDK namespace quotas and Provisioner cleanup preserve prepaid blob capacity."""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

import httpx
from sqlalchemy import select

import test_source_provisioning as source_fixtures

from hf2l_exchange.client import ExchangeClient, ExchangeError
from hf2l_jobs.blob_budget import KIND, checkpoint_budget, require_blob_budget
from hf2l_jobs.broker import principal_id
from hf2l_jobs.models import Job, Pool, Project, ProvisioningOperation
from hf2l_jobs.provisioning import Provisioner
from hf2l_jobs.resources import ResourceError
from hf2l_jobs.retention import RetentionService
from hf2l_jobs.source import SourceError


class BlobProvisioningTests(unittest.TestCase):
    """Exercise provisioning with real SDK request serialization and lost replies."""

    def setUp(self):
        self.fixture = source_fixtures.ProvisioningHTTPTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        fixture = self.fixture
        fixture.http.close()
        fixture.exchange.close()
        self.database = fixture.database
        self.requests = []
        self.spaces = {}
        self.lose_create_reply = False
        self.policy_overrides = {}
        self.managed_overrides = {}
        self.retirement_reply_pending = False
        self.cleanup_observation = {
            "space_id": "space", "job_id": fixture.job.id,
            "status": "retired", "cleanup_pending": False,
        }
        with self.database.transaction() as session:
            objects = session.get(Pool, "objects")
            if objects is None:
                session.add(Pool(id="objects", name="Approved Exchange objects", node_id="exchange-node",
                    cpu_millicores=0, memory_bytes=0, disk_bytes=8 * 1024**3,
                    healthy=True, details_json={"object_store": True}))
            else:
                self.assertTrue(objects.details_json["object_store"])
                self.assertEqual((objects.cpu_millicores, objects.memory_bytes, objects.gpu_uuids), (0, 0, []))
        fixture.http = httpx.Client(transport=httpx.MockTransport(self._request))
        fixture.exchange = ExchangeClient("https://exchange.example.invalid", "control-plane-only",
                                         http=fixture.http, retries=1)
        self.provisioner = Provisioner(self.database, fixture.exchange, fixture.catalog,
            fixture.root / "jobs", workload_issuer=fixture.workload_issuer,
            exchange_storage_pool_id="objects",
            execution_bindings=lambda job, attempt, component, space, principal: {
                "certificate_thumbprint": "a" * 43,
                "proxy_endpoint": str(fixture.root / "jobs" / job.id / "attempts" /
                                      attempt.id / component.component_id / "proxy.sock"),
            })
        self.retention = RetentionService(self.database)
        self.budget = checkpoint_budget(fixture.spec)

    def _request(self, request):
        self.requests.append(request)
        fixture = self.fixture
        path = request.url.path
        body = json.loads(request.content) if request.content else {}
        if path == "/v2/spaces" and request.method == "POST":
            prepaid = require_blob_budget(self.database, fixture.job,
                for_cleanup=fixture.job.state in {"SUCCEEDED", "FAILED", "CANCELLED"})
            self.assertEqual(body["quota_bytes"], prepaid["quota_bytes"])
            self.assertEqual(body["principal_quota_bytes"], prepaid["principal_quota_bytes"])
            self.assertEqual(prepaid["pool_id"], "objects")
            self.assert_held(self.budget.quota_bytes)
            key = request.headers["Idempotency-Key"]
            response = self.spaces.setdefault(key, {"id": "space", "name": body["name"],
                "profile": body["profile"], "quota_bytes": body["quota_bytes"],
                "principal_quota_bytes": body["principal_quota_bytes"]})
            if self.lose_create_reply:
                self.lose_create_reply = False
                raise httpx.ReadTimeout("Accepted namespace creation response was lost")
        elif path == "/v2/spaces/space" and request.method == "GET":
            self.assertTrue(self.spaces, "No namespace was ever accepted")
            response = {**next(iter(self.spaces.values())), **self.policy_overrides}
        elif path.endswith("/managed/retire"):
            self.assertEqual(body, {"job_id": fixture.job.id})
            response = {"space_id": "space", "job_id": fixture.job.id, "status": "retired",
                        "cleanup_pending": self.retirement_reply_pending}
        elif path.endswith("/managed") and request.method == "GET":
            response = dict(self.cleanup_observation)
        elif path.endswith("/managed"):
            response = {"space_id": "space", "job_id": body["job_id"], "managed": True,
                        **self.managed_overrides}
        elif "/types/" in path:
            kind = path.split("/types/")[1].split("/")[0]
            response = {"id": "schema-" + kind, "kind": kind, "schema": body["schema"], "revision": 1}
        elif "/members/" in path:
            response = {"principal_id": path.rsplit("/", 1)[-1], **body}
        elif path.endswith("/workload-grants/revoke"):
            response = {"attempt_id": body["attempt_id"], "revoked": 1, "revoked_at": 1}
        elif path.endswith("/workload-grants"):
            key = request.headers["Idempotency-Key"]
            response = fixture.grants.setdefault(key, {**body, "space_id": "space",
                "grant_id": "grant", "principal_id": principal_id(fixture.workload_issuer, body["subject"]),
                "enabled": True})
        elif path.endswith("/refs/main"):
            return httpx.Response(404, json={"error": {"code": "reference_not_found"}})
        else:
            raise AssertionError((request.method, path))
        return httpx.Response(200, json=response)

    def reserve(self):
        fixture = self.fixture
        plans = self.provisioner.admission_storage(fixture.job)
        blob = [plan for plan in plans if plan["kind"] == KIND]
        self.assertEqual(len(blob), 1)
        plan = blob[0]
        self.assertEqual(plan["pool_id"], "objects")
        self.assertEqual(plan["max_bytes"], self.budget.quota_bytes)
        self.assertEqual(plan["details"]["principal_quota_bytes"], self.budget.principal_quota_bytes)
        rid = self.provisioner.ledger.own(job_id=fixture.job.id, attempt_id=fixture.attempt.id,
            component_id=plan["component_id"], kind=plan["kind"], external_id=plan["external_id"],
            details=plan["details"], retained=True)
        self.retention.reserve_resource(rid, fixture.job.id, plan["max_bytes"])
        return rid

    def ensure(self):
        return self.provisioner.ensure(self.fixture.job, self.fixture.attempt)

    def rows(self):
        return self.provisioner.ledger.resources(self.fixture.job.id, kind=KIND)

    def assert_held(self, amount):
        with self.database.transaction(immediate=False) as session:
            self.assertEqual(RetentionService.pool_used_bytes(session, "objects"), amount)
            self.assertGreaterEqual(session.get(Project, "project").retained_bytes, amount)
        if amount:
            row, = self.rows()
            self.assertEqual(row["size_bytes"], amount)
            self.assertEqual(row["details"]["retention_charged_bytes"], amount)
            self.assertFalse(row["details"]["retention_charge_released"])

    def terminal(self):
        self.fixture.job.state = "FAILED"
        with self.database.transaction() as session:
            session.get(Job, self.fixture.job.id).state = "FAILED"

    def project_bytes(self):
        with self.database.transaction(immediate=False) as session:
            return session.get(Project, "project").retained_bytes

    def test_unpaid_budget_blocks_source_fetch_and_namespace_creation(self):
        registry = self.fixture.catalog.source_registry
        with patch.object(registry, "materialize", wraps=registry.materialize) as materialize:
            with self.assertRaises(ResourceError):
                self.ensure()
            materialize.assert_not_called()
        self.assertEqual(self.requests, [])
        self.assertFalse((self.provisioner.root / self.fixture.job.id / "source").exists())
        self.assertEqual(self.project_bytes(), 0)

    def test_approved_object_pool_is_required_by_admission_before_side_effects(self):
        self.provisioner.exchange_storage_pool_id = None
        with self.assertRaises(ResourceError):
            self.provisioner.admission_storage(self.fixture.job)
        self.assertEqual(self.requests, [])
        self.assertFalse((self.provisioner.root / self.fixture.job.id).exists())

    def test_prepaid_allowance_precedes_fetch_and_sdk_sends_exact_limits_once(self):
        self.reserve()
        registry = self.fixture.catalog.source_registry
        materialize = registry.materialize
        fetch_observations = []
        def inspect_fetch(*args, **kwargs):
            prepaid = require_blob_budget(self.database, self.fixture.job)
            fetch_observations.append(prepaid)
            self.assert_held(self.budget.quota_bytes)
            return materialize(*args, **kwargs)
        with patch.object(registry, "materialize", side_effect=inspect_fetch):
            first = self.ensure()
            charged = self.project_bytes()
            second = self.ensure()
        self.assertEqual(len(fetch_observations), 1)
        self.assertEqual(first.space_id, second.space_id)
        self.assertEqual(self.project_bytes(), charged)
        posts = [request for request in self.requests
                 if request.method == "POST" and request.url.path == "/v2/spaces"]
        self.assertEqual(len(posts), 1)
        body = json.loads(posts[0].content)
        self.assertEqual((body["quota_bytes"], body["principal_quota_bytes"]),
                         (self.budget.quota_bytes, self.budget.principal_quota_bytes))
        self.assertEqual(len(self.spaces), 1)
        self.assertEqual(self.rows()[0]["details"]["space_id"], "space")
        self.assert_held(self.budget.quota_bytes)

    def test_lost_creation_ack_replays_stable_key_limits_without_double_charge(self):
        self.reserve()
        self.lose_create_reply = True
        with self.assertRaises(ExchangeError):
            self.ensure()
        charge = self.project_bytes()
        self.assert_held(self.budget.quota_bytes)
        with self.database.transaction(immediate=False) as session:
            operation = session.scalar(select(ProvisioningOperation).where(
                ProvisioningOperation.job_id == self.fixture.job.id,
                ProvisioningOperation.operation == "exchange_space"))
            self.assertEqual(operation.state, "unknown")
        self.ensure()
        self.ensure()
        posts = [request for request in self.requests
                 if request.method == "POST" and request.url.path == "/v2/spaces"]
        self.assertEqual(len(posts), 2)
        self.assertEqual(posts[0].headers["Idempotency-Key"], posts[1].headers["Idempotency-Key"])
        self.assertEqual(posts[0].content, posts[1].content)
        self.assertEqual(len(self.spaces), 1)
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.project_bytes(), charge)
        self.assert_held(self.budget.quota_bytes)

    def test_replay_rejects_foreign_or_drifted_actual_namespace_policy(self):
        self.reserve()
        self.ensure()
        baseline_charge = self.project_bytes()
        for key, value in (("id", "foreign-space"),
                           ("quota_bytes", self.budget.quota_bytes + 1),
                           ("principal_quota_bytes", self.budget.principal_quota_bytes + 1)):
            with self.subTest(field=key):
                self.policy_overrides = {key: value}
                with self.assertRaises(ResourceError):
                    self.ensure()
                self.assertEqual(self.project_bytes(), baseline_charge)
                self.assert_held(self.budget.quota_bytes)
        self.policy_overrides = {}
        self.ensure()
        self.assertEqual(len(self.spaces), 1)

    def _foreign_managed_receipt(self, field, foreign):
        self.reserve()
        self.managed_overrides = {field: foreign}
        with self.assertRaises(ResourceError):
            self.ensure()
        self.assert_held(self.budget.quota_bytes)
        self.assertEqual(len(self.spaces), 1)
        self.assertFalse(any(request.url.path.endswith("/workload-grants")
                             for request in self.requests))
        self.assertEqual(self.provisioner.ledger.resources(self.fixture.job.id,
                                                          kind="workload_grant"), [])

    def test_foreign_managed_job_receipt_blocks_worker_grants(self):
        self._foreign_managed_receipt("job_id", "foreign-job")

    def test_foreign_managed_space_receipt_blocks_worker_grants(self):
        self._foreign_managed_receipt("space_id", "foreign-space")

    def test_pending_retirement_holds_pool_and_project_until_current_get_confirms(self):
        self.reserve()
        self.ensure()
        self.terminal()
        before = self.project_bytes()
        self.retirement_reply_pending = False
        self.cleanup_observation["cleanup_pending"] = True
        self.assertFalse(self.provisioner.purge_job(self.fixture.job))
        self.assertEqual(self.project_bytes(), before)
        self.assert_held(self.budget.quota_bytes)
        self.assertTrue((self.provisioner.root / self.fixture.job.id / "source").exists())
        self.retirement_reply_pending = True
        self.cleanup_observation["cleanup_pending"] = False
        self.assertTrue(self.provisioner.purge_job(self.fixture.job))
        self.assert_held(0)
        self.assertEqual(self.project_bytes(), before - self.budget.quota_bytes)
        row, = self.rows()
        self.assertEqual(row["state"], "deleted")
        self.assertTrue(row["details"]["blob_cleanup_confirmed"])
        self.assertTrue(row["details"]["retention_charge_released"])
        released = self.project_bytes()
        self.assertTrue(self.provisioner.purge_job(self.fixture.job))
        self.assertEqual(self.project_bytes(), released)
        self.assert_held(0)
        retirements = [request for request in self.requests if request.url.path.endswith("/managed/retire")]
        self.assertEqual(retirements[0].headers["Idempotency-Key"],
                         retirements[1].headers["Idempotency-Key"])

    def test_foreign_get_cleanup_proof_cannot_release_even_after_retire_ack(self):
        self.reserve()
        self.ensure()
        self.terminal()
        before = self.project_bytes()
        for key, value in (("space_id", "foreign-space"), ("job_id", "foreign-job"),
                           ("status", "active"), ("cleanup_pending", 0)):
            with self.subTest(field=key):
                self.cleanup_observation = {"space_id": "space", "job_id": self.fixture.job.id,
                    "status": "retired", "cleanup_pending": False, key: value}
                self.assertFalse(self.provisioner.purge_job(self.fixture.job))
                self.assertEqual(self.project_bytes(), before)
                self.assert_held(self.budget.quota_bytes)
        self.cleanup_observation = {"space_id": "space", "job_id": self.fixture.job.id,
            "status": "retired", "cleanup_pending": False}
        self.assertTrue(self.provisioner.purge_job(self.fixture.job))
        self.assert_held(0)

    def test_failed_source_with_durable_no_namespace_request_releases_only_at_purge(self):
        self.reserve()
        with patch.object(self.fixture.catalog.source_registry, "materialize",
                          side_effect=SourceError("Approved source fetch failed")):
            with self.assertRaises(SourceError):
                self.ensure()
        self.assertEqual(self.requests, [])
        self.assert_held(self.budget.quota_bytes)
        with self.database.transaction(immediate=False) as session:
            self.assertIsNone(session.scalar(select(ProvisioningOperation.id).where(
                ProvisioningOperation.job_id == self.fixture.job.id,
                ProvisioningOperation.operation == "exchange_space")))
        self.terminal()
        self.assert_held(self.budget.quota_bytes)
        self.assertTrue(self.provisioner.purge_job(self.fixture.job))
        self.assert_held(0)
        row, = self.rows()
        self.assertTrue(row["details"]["blob_unused_confirmed"])
        self.assertTrue(row["details"]["retention_charge_released"])
        self.assertEqual(self.requests, [])
        self.retention.confirm_job_data_deleted(self.fixture.job.id)
        self.assertEqual(self.project_bytes(), 0)

    def test_unknown_creation_cannot_be_converted_into_unused_absence_proof(self):
        self.reserve()
        self.lose_create_reply = True
        with self.assertRaises(ExchangeError):
            self.ensure()
        self.terminal()
        before = self.project_bytes()
        # A reconciler may adopt the accepted request; uncertain cleanup still
        # cannot become a proof that the remote namespace never existed.
        self.cleanup_observation["cleanup_pending"] = True
        self.assertFalse(self.provisioner.purge_job(self.fixture.job))
        self.assertEqual(self.project_bytes(), before)
        self.assert_held(self.budget.quota_bytes)
        row, = self.rows()
        self.assertFalse(row["details"].get("blob_unused_confirmed", False))
        self.assertEqual(len(self.spaces), 1)
