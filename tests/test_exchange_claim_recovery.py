"""Durable claim recovery through the SDK, authenticated HTTP API, and database.

The transport only injects outages or lost responses. Acquisition, abandonment,
renewal, completion, and idempotent replay all use the actual service.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import unittest
from urllib.parse import urlsplit

import numpy as np
from safetensors.numpy import load_file, save_file

from hf2l.core.ports import ClaimInactive, PublicationUncertain, RoundContext
from hf2l.core.protocol import ROUND_FILE, SUBMISSION_FILE
from hf2l.fedavg_runner import FedAvgRunner, RunState
from hf2l.hub_helpers import artifact_hashes, regular_file_paths, write_json
from hf2l.round.config import RoundConfig


_fixture = Path(__file__).resolve().parents[1] / "packages/exchange/tests/support.py"
_exchange_available = all(importlib.util.find_spec(name) is not None for name in (
    "boto3", "moto", "sqlalchemy", "jwt", "fastapi", "httpx", "cryptography", "hf2l_exchange"))
if not _exchange_available and os.environ.get("EXCHANGE_REQUIRE_TESTS") == "1":
    raise ImportError("The Exchange claim recovery tests require the exchange service/test dependencies")
if _exchange_available:
    import httpx
    from sqlalchemy import select

    from hf2l.backends.exchange import ExchangeStore
    from hf2l_exchange.client import ExchangeClient, ExchangeError
    from hf2l_exchange.models import Coordination
    from hf2l_exchange.worker import tick

    _spec = importlib.util.spec_from_file_location("exchange_claim_recovery_support", _fixture)
    _support = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_support)
    _ExchangeTestCase = _support.ExchangeTestCase
else:
    _ExchangeTestCase = unittest.TestCase


class FaultTransport:
    def __init__(self, http, state_path):
        self.http, self.state_path = http, state_path
        self.metadata_paths = set()
        self.metadata_failures = 0
        self.metadata_states = []
        self.faults = {}

    @staticmethod
    def unavailable():
        return httpx.Response(503, json={"error": {"code": "injected_outage"}})

    def request(self, method, url, **kwargs):
        path = urlsplit(url).path
        if method == "GET" and path in self.metadata_paths and self.metadata_failures:
            self.metadata_failures -= 1
            self.metadata_states.append(json.loads(self.state_path.read_text()))
            return self.unavailable()
        for suffix, fault in self.faults.items():
            if method == "POST" and "/acquisitions" in path and path.endswith(suffix) and fault[1]:
                fault[1] -= 1
                if fault[0] == "after":
                    self.http.request(method, url, **kwargs)
                return self.unavailable()
        return self.http.request(method, url, **kwargs)


@unittest.skipUnless(_exchange_available, "Exchange integration dependencies are optional")
class ExchangeClaimRecoveryTests(_ExchangeTestCase):
    def setUp(self):
        super().setUp()
        self.state_path = self.directory / "same-run-state.json"
        self.transport = FaultTransport(self.client, self.state_path)
        self.owner = self.sdk("owner")
        self.store = ExchangeStore(None, None, client=self.owner, wait_seconds=15)
        self.sid = self.new_space("recovery", profile="fedavg.v1")["id"]
        self.global_type = self.register_type("model.global", publish_roles=["publisher"], space=self.sid)
        self.update_type = self.register_type("training.update", visibility="private",
                                              publish_roles=["contributor"], space=self.sid)
        self.run_count = 0

    def sdk(self, subject):
        sdk = ExchangeClient("http://127.0.0.1", self.auth(subject)["Authorization"].split(" ", 1)[1],
                             http=self.transport, allow_local_http=True, sleep=lambda _: tick(self.transfers))
        self.addCleanup(sdk.close)
        return sdk

    def prepare(self, *, checkpoints=False):
        if checkpoints:
            initial = self.checkpoint("initial", 0)
            write_json(initial / ROUND_FILE, {
                "schema_version": 2, "backend": "exchange", "round": 0,
                "checkpoint_files_sha256": artifact_hashes(initial, ["config.json", "model.safetensors"]),
            })
            self.base = self.store.initialize_repository(self.sid, initial, private=True).revision
        else:
            self.base = self.owner.put_record(self.sid, kind="model.global",
                schema_revision_id=self.global_type["id"], metadata={"inputs": [], "hf2l_files": {
                    ROUND_FILE: {"schema_version": 2, "backend": "exchange", "round": 0},
                }}).id
            self.owner.set_ref(self.sid, "main", self.base)
        self.submitted = []
        for name, count in (("alice", 1), ("bob", 3)):
            self.member(name, ["reader", "contributor"], {"participant": name}, space=self.sid)
            client = self.sdk(name)
            if checkpoints:
                folder = self.checkpoint(name, count)
                write_json(folder / SUBMISSION_FILE, {
                    "schema_version": 2, "backend": "exchange", "repo_id": self.sid,
                    "base_revision": self.base, "source_round": 0, "participant": name,
                    "num_examples": count,
                    "checkpoint_files_sha256": artifact_hashes(folder, ["config.json", "model.safetensors"]),
                })
                store = ExchangeStore(None, None, client=client, wait_seconds=15)
                record = store.publish_submission(self.sid, folder, regular_file_paths(folder),
                    participant=name, source_round=0, base_revision=self.base, submission_revision=None).revision
            else:
                record = client.put_record(self.sid, kind="training.update",
                    schema_revision_id=self.update_type["id"], metadata={
                        "base_record_id": self.base, "sample_count": count, "hf2l_files": {},
                    }).id
            self.submitted.append(record)
        self.context = RoundContext(self.sid, self.store.resolve_reference(self.sid), 0)
        self.transport.metadata_paths = {f"/v2/spaces/{self.sid}/records/{rid}" for rid in self.submitted}

    def checkpoint(self, name, value):
        folder = self.directory / name
        folder.mkdir()
        write_json(folder / "config.json", {"model_type": "test"})
        save_file({"weight": np.asarray([value], dtype=np.float32)}, folder / "model.safetensors")
        return folder

    def run_round(self, **options):
        self.run_count += 1
        return FedAvgRunner(self.store).run(RoundConfig(
            self.sid, self.directory / f"output-{self.run_count}", selection="claim", publish=True,
            run_state=self.state_path, claim_lease_seconds=60, **options,
        ))

    def attempts(self):
        with self.service.read_sessions.begin() as session:
            return [(a.id, a.fence, a.state) for a in session.scalars(
                select(Coordination).where(Coordination.space_id == self.sid).order_by(Coordination.fence))]

    def seed_saved_claim(self, *, terminal=None, remember=False):
        state = RunState(self.state_path)
        try:
            saved = state.acquire(self.context, 60)
            handle = self.store.acquire_claim(self.sid, context=self.context,
                acquisition_key=saved["acquisition_key"], lease_seconds=60)
            if remember:
                state.remember(handle)
            if terminal == "abandoned":
                self.store.abandon_claim(self.sid, handle)
            elif terminal == "expired":
                with self.service.sessions.begin() as session:
                    session.get(Coordination, handle.id).lease_until = 1
            return json.loads(self.state_path.read_text()), handle
        finally:
            state.close()

    def assert_metadata_outage(self):
        self.transport.metadata_failures = self.owner.retries
        with self.assertRaises(ExchangeError) as caught:
            self.run_round()
        self.assertEqual(caught.exception.code, "injected_outage")
        self.assertEqual(len(self.transport.metadata_states), self.owner.retries)

    def assert_reaches_manifest_validation(self, **options):
        # Metadata-only inputs intentionally have no submission manifest. This
        # proves claim recovery succeeded without confusing it with blob I/O.
        with self.assertRaisesRegex(ValueError, "at least two eligible"):
            self.run_round(**options)

    def test_metadata_outage_is_persisted_before_read_and_retry_publishes(self):
        self.prepare(checkpoints=True)
        self.assert_metadata_outage()
        first_id, first_fence, state = self.attempts()[0]
        self.assertEqual(state, "abandoned")
        self.assertTrue(all(s["claim_id"] == first_id for s in self.transport.metadata_states))
        self.assertFalse(self.state_path.exists())
        result = self.run_round()
        self.assertEqual(result.status, "published")
        self.assertEqual([2.5], load_file(result.aggregate_dir / "model.safetensors")["weight"].tolist())
        attempts = self.attempts()
        self.assertEqual([a[2] for a in attempts], ["abandoned", "completed"])
        self.assertGreater(attempts[1][1], first_fence)
        self.assertFalse(self.state_path.exists())

    def test_lost_abandon_response_reconciles_before_replacing_key(self):
        self.prepare()
        self.transport.faults["/abandon"] = ["after", self.owner.retries]
        self.assert_metadata_outage()
        saved = json.loads(self.state_path.read_text())
        self.assertEqual(self.attempts(), [(saved["claim_id"], saved["fence"], "abandoned")])
        self.assert_reaches_manifest_validation()
        self.assertEqual([a[2] for a in self.attempts()], ["abandoned", "abandoned"])
        self.assertGreater(self.attempts()[1][1], saved["fence"])
        self.assertFalse(self.state_path.exists())

    def test_abandon_outage_preserves_and_resumes_active_acquisition(self):
        self.prepare()
        self.transport.faults["/abandon"] = ["before", self.owner.retries]
        self.assert_metadata_outage()
        saved = json.loads(self.state_path.read_text())
        self.assertEqual(self.attempts(), [(saved["claim_id"], saved["fence"], "active")])
        self.assert_reaches_manifest_validation()
        self.assertEqual(self.attempts(), [(saved["claim_id"], saved["fence"], "abandoned")])

    def test_legacy_key_only_abandoned_state_recovers(self):
        self.prepare()
        saved, claim = self.seed_saved_claim(terminal="abandoned")
        self.assertNotIn("claim_id", saved)
        self.assert_reaches_manifest_validation()
        self.assertEqual(len(self.attempts()), 2)
        self.assertGreater(self.attempts()[1][1], claim.fence)

    def test_expired_key_only_state_recovers_using_server_clock(self):
        self.prepare()
        _, claim = self.seed_saved_claim(terminal="expired")
        self.assert_reaches_manifest_validation()
        self.assertEqual([a[2] for a in self.attempts()], ["expired", "abandoned"])
        self.assertGreater(self.attempts()[1][1], claim.fence)

    def test_expired_known_claim_recovers_after_failed_renewal(self):
        self.prepare()
        _, claim = self.seed_saved_claim(terminal="expired", remember=True)
        self.assert_reaches_manifest_validation()
        self.assertEqual([a[2] for a in self.attempts()], ["expired", "abandoned"])
        self.assertGreater(self.attempts()[1][1], claim.fence)

    def test_lost_acquire_response_replays_same_key_without_another_claim(self):
        self.prepare()
        self.transport.faults["/acquisitions"] = ["after", self.owner.retries]
        with self.assertRaises(ExchangeError):
            self.run_round()
        saved = json.loads(self.state_path.read_text())
        self.assertNotIn("claim_id", saved)
        original = self.attempts()[0]
        self.assertEqual(original[2], "active")
        self.assert_reaches_manifest_validation()
        self.assertEqual(self.attempts(), [(original[0], original[1], "abandoned")])

    def test_acquire_outage_preserves_original_key(self):
        self.prepare()
        saved, _ = self.seed_saved_claim(terminal="abandoned")
        self.transport.faults["/acquisitions"] = ["before", self.owner.retries]
        with self.assertRaises(ExchangeError):
            self.run_round()
        self.assertEqual(json.loads(self.state_path.read_text()), saved)
        self.assertEqual(len(self.attempts()), 1)

    def test_renewal_outage_preserves_known_active_claim(self):
        self.prepare()
        saved, claim = self.seed_saved_claim(remember=True)
        self.transport.faults["/renew"] = ["before", self.owner.retries]
        with self.assertRaises(ExchangeError):
            self.run_round()
        self.assertEqual(json.loads(self.state_path.read_text()), saved)
        self.assertEqual(self.attempts(), [(claim.id, claim.fence, "active")])

    def test_direct_adapter_descriptor_outage_leaves_key_replayable(self):
        self.prepare()
        saved, claim = self.seed_saved_claim()
        self.transport.metadata_failures = self.owner.retries
        with self.assertRaises(ExchangeError):
            self.store.claim_submissions(self.sid, context=self.context,
                acquisition_key=saved["acquisition_key"], lease_seconds=60)
        self.assertEqual(self.attempts(), [(claim.id, claim.fence, "active")])
        replayed, candidates = self.store.claim_submissions(self.sid, context=self.context,
            acquisition_key=saved["acquisition_key"], lease_seconds=60)
        self.assertEqual(replayed.id, claim.id)
        self.assertEqual({c.revision for c in candidates}, set(self.submitted))

    def test_explicit_abandoned_claim_is_not_replaced(self):
        self.prepare()
        saved, claim = self.seed_saved_claim(terminal="abandoned", remember=True)
        with self.assertRaises(ClaimInactive):
            self.run_round(claim_id=claim.id)
        self.assertEqual(json.loads(self.state_path.read_text()), saved)
        self.assertEqual(len(self.attempts()), 1)

    def test_lost_completion_response_preserves_evidence_and_blocks_reaggregation(self):
        self.prepare(checkpoints=True)
        self.transport.faults["/complete"] = ["after", self.owner.retries]
        with self.assertRaises(PublicationUncertain):
            self.run_round()
        saved = json.loads(self.state_path.read_text())
        completed = self.owner.get_acquisition(self.sid, saved["claim_id"])
        self.assertEqual(completed.state, "completed")
        self.assertEqual(self.owner.resolve(self.sid, "main").record_id, completed.result_record_id)
        # A caller replaying the old context receives concrete reconciliation
        # evidence, never an inactive signal that could authorize key rotation.
        for claim_id in (None, saved["claim_id"]):
            with self.subTest(claim_id=claim_id), self.assertRaisesRegex(
                    PublicationUncertain, completed.result_record_id):
                self.store.acquire_claim(self.sid, context=self.context,
                    acquisition_key=saved["acquisition_key"], claim_id=claim_id, lease_seconds=60)
        with self.assertRaisesRegex(ValueError, "different round.*reconcile"):
            self.run_round()
        self.assertEqual(json.loads(self.state_path.read_text()), saved)
        self.assertEqual(len(self.attempts()), 1)


if __name__ == "__main__":
    unittest.main()
