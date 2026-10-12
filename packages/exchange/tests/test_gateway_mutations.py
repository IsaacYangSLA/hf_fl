"""Gateway PUT reservations fence physical cleanup until the call is settled.

These are database/service tests with a deterministic blob provider. Provider
network behavior is qualified separately; no fake provider success clears an
uncertain gateway reservation.
"""
from dataclasses import replace
from hashlib import sha256
import json
from threading import Event, Thread
import unittest

from sqlalchemy import select

from hf2l_exchange.domain import ExchangeError
from hf2l_exchange.models import Blob, ManagedSpace, Record, Space, TransferAttempt, WorkloadGrant, database_time
from hf2l_exchange.transfers import TransferService, inspect_mutations, repair_mutations
from hf2l_exchange.worker import tick

from test_transfers import FakeStore
from test_workload_grants import ManagedSpaceFixture


class GatewayMutationTests(ManagedSpaceFixture):
    def setUp(self):
        super().setUp()
        self.storage = FakeStore()
        self.transfers = TransferService(self.service, self.storage)
        self.record = self.document("gateway-document")
        self.attachment = self.record["attachments"][0]["id"]
        self.args = self.space_id, self.record["id"], self.attachment, self.workload
        self.initiated = self.transfers.initiate(*self.args)
        self.attempt_id = self.initiated["attempt_id"]

    def document(self, key):
        return self.service.create_record(self.workload, self.space_id, {
            "kind": "document", "schema_revision_id": self.revision["id"], "metadata": {},
            "attachments": [{"path": "document.bin", "size": 3, "sha256": sha256(b"abc").hexdigest()}],
        }, key)

    def attempt(self, attempt_id=None):
        with self.service.sessions.begin() as session:
            return session.get(TransferAttempt, attempt_id or self.attempt_id)

    def begin(self, *, principal=None, space_id=None, record_id=None, attachment_id=None, number=1):
        handle, grant = self.transfers.begin_gateway_put(
            principal or self.workload, space_id or self.space_id,
            record_id or self.record["id"], attachment_id or self.attachment, number)
        self.assertEqual(grant["number"], number)
        self.assertEqual(grant["size"], 3)
        return handle

    def retire(self):
        self.service.revoke_workload_grants(self.owner, self.space_id,
                                           {"attempt_id": "attempt-a"}, "gateway-revoke")
        return self.service.retire_managed_space(self.owner, self.space_id,
                                                {"job_id": "job-a"}, "gateway-retire")

    def due(self):
        with self.service.sessions.begin() as session:
            attempt = session.get(TransferAttempt, self.attempt_id)
            attempt.next_attempt = 0
            attempt.lease_until = None
            attempt.token = None
            attempt.grant_expires_at = 0
            session.get(Blob, self.attachment).grant_expires_at = 0

    def assert_no_mutation(self):
        with self.service.sessions() as session:
            attempts = session.scalars(select(TransferAttempt)).all()
            self.assertTrue(all(not attempt.mutation_tokens for attempt in attempts))
        self.assertEqual(self.storage.cleaned, [])

    def test_begin_persists_one_marker_before_any_provider_io(self):
        calls = []
        def sign():
            self.assertEqual(len(self.attempt().mutation_tokens), 1)
            calls.append("signed-after-persisted-fence")
        self.storage.on_grant = sign
        handle = self.begin()
        self.assertIsNotNone(handle)
        attempt = self.attempt()
        self.assertEqual(len(attempt.mutation_tokens), 1)
        self.assertEqual(attempt.state, "uploading")
        self.assertEqual(calls, ["signed-after-persisted-fence"])
        self.assertEqual(self.storage.cleaned, [])
        # A new service instance observes the durable reservation.
        restarted = TransferService(self.service, self.storage)
        self.assertEqual(inspect_mutations(restarted.service, [attempt.id])["attempts"][0]["mutation_count"], 1)
        restarted.finish_gateway_put(handle)
        self.assertEqual(self.attempt().mutation_tokens, [])

    def test_in_flight_put_blocks_retirement_cleanup_then_known_finish_releases_it(self):
        writer_started, finish_allowed = Event(), Event()
        observed, errors = [], []

        def writer():
            try:
                handle = self.begin()
                observed.append(tuple(self.attempt().mutation_tokens))
                writer_started.set()
                if not finish_allowed.wait(5):
                    raise AssertionError("Test never released the gateway writer")
                # This known completion models the gateway's closed response
                # stream; finish is deliberately absent before this event.
                self.transfers.finish_gateway_put(handle)
            except BaseException as error:
                errors.append(error)
                writer_started.set()

        thread = Thread(target=writer, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(finish_allowed.set)
        self.assertTrue(writer_started.wait(5), "Gateway writer did not reserve its call")
        self.assertEqual(errors, [])
        self.assertEqual(len(observed[0]), 1)
        retired = self.retire()
        self.assertTrue(retired["cleanup_pending"])
        self.due()
        self.assertEqual(tick(self.transfers)["cleaned"], 0)
        self.assertEqual(self.storage.cleaned, [], "A live writer must prevent provider cleanup")
        with self.service.sessions() as session:
            self.assertEqual(session.get(Space, self.space_id).reclaiming, 3)
            self.assertTrue(session.get(Blob, self.attachment).pending_deletion)
        self.assertTrue(self.service.get_managed_space(self.owner, self.space_id)["cleanup_pending"])
        finish_allowed.set()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        settled = self.attempt()
        self.assertEqual(settled.mutation_tokens, [])
        self.assertEqual(settled.state, "cleanup")
        # Finishing a known call must cancel the old cleanup backoff and fence
        # its stale worker lease, so retirement can proceed immediately.
        self.assertIsNone(settled.token)
        self.assertIsNone(settled.lease_until)
        self.assertEqual(tick(self.transfers)["cleaned"], 1)
        self.assertEqual(self.storage.cleaned, [self.attempt().object_key])
        self.assertFalse(self.service.get_managed_space(self.owner, self.space_id)["cleanup_pending"])
        with self.service.sessions() as session:
            self.assertEqual(session.get(Space, self.space_id).reclaiming, 0)
            self.assertEqual(session.get(Blob, self.attachment).state, "cleaned")
            self.assertIsNotNone(session.get(Record, self.record["id"]))
            self.assertIsNotNone(session.get(ManagedSpace, self.space_id))

    def test_expired_database_lease_and_unknown_call_age_never_clear_marker(self):
        self.begin()  # Lost gateway process: no completion receipt.
        marker = tuple(self.attempt().mutation_tokens)
        self.retire()
        with self.service.sessions.begin() as session:
            attempt = session.get(TransferAttempt, self.attempt_id)
            attempt.created_at = attempt.updated_at = 0
        restarted = TransferService(self.service, self.storage)
        for _ in range(3):
            self.due()
            self.assertEqual(tick(restarted)["cleaned"], 0)
            self.assertEqual(tuple(self.attempt().mutation_tokens), marker)
            self.assertEqual(self.storage.cleaned, [])
        self.assertTrue(self.service.get_managed_space(self.owner, self.space_id)["cleanup_pending"])
        self.assertEqual(repair_mutations(self.service, [self.attempt_id])["attempts"][0]["mutation_count"], 1)
        with self.assertRaises(ExchangeError):
            repair_mutations(self.service, [self.attempt_id], execute=True, writers_stopped=True)
        self.assertEqual(tuple(self.attempt().mutation_tokens), marker)

    def test_known_finish_clears_only_its_token_and_is_safe_to_repeat(self):
        first = self.begin()
        second = self.begin()
        self.assertEqual(len(self.attempt().mutation_tokens), 2)
        self.transfers.finish_gateway_put(first)
        remaining = tuple(self.attempt().mutation_tokens)
        self.assertEqual(len(remaining), 1)
        self.transfers.finish_gateway_put(first)
        self.assertEqual(tuple(self.attempt().mutation_tokens), remaining)
        self.transfers.finish_gateway_put(second)
        self.assertEqual(self.attempt().mutation_tokens, [])

    def test_finish_does_not_clear_another_attachment_reservation(self):
        other = self.document("gateway-other-document")
        other_attachment = other["attachments"][0]["id"]
        other_args = self.space_id, other["id"], other_attachment, self.workload
        other_attempt_id = self.transfers.initiate(*other_args)["attempt_id"]
        first = self.begin()
        second = self.begin(record_id=other["id"], attachment_id=other_attachment)
        other_tokens = tuple(self.attempt(other_attempt_id).mutation_tokens)
        self.assertTrue(self.transfers.finish_gateway_put(first))
        self.assertEqual(self.attempt().mutation_tokens, [])
        self.assertEqual(tuple(self.attempt(other_attempt_id).mutation_tokens), other_tokens)
        self.transfers.finish_gateway_put(second)
        self.assertEqual(self.attempt(other_attempt_id).mutation_tokens, [])


    def test_forged_receipt_binding_cannot_clear_the_original_or_sibling_marker(self):
        sibling = self.begin()
        alterations = (
            {"space_id": "foreign-space"}, {"record_id": "foreign-record"},
            {"attachment_id": "foreign-attachment"}, {"attempt_id": "foreign-attempt"},
            {"object_key": "foreign-job/object"}, {"upload_id": "foreign-upload"},
            {"part_number": 2}, {"part_number": True}, {"part_number": "1"},
            {"token": "gateway-put-not-reserved"},
        )
        for fields in alterations:
            handle = self.begin()
            before = tuple(self.attempt().mutation_tokens)
            with self.subTest(fields=fields):
                try:
                    self.assertFalse(self.transfers.finish_gateway_put(replace(handle, **fields)))
                    self.assertEqual(tuple(self.attempt().mutation_tokens), before)
                finally:
                    # Independent cases: a broken implementation must not make
                    # later forged-receipt cases pass due to a missing marker.
                    self.transfers.finish_gateway_put(handle)
            self.assertEqual(tuple(self.attempt().mutation_tokens), (sibling.token,))
        self.assertTrue(self.transfers.finish_gateway_put(sibling))

    def test_human_and_service_principals_cannot_open_gateway_put_reservations(self):
        for actor in (self.owner, self.broker, self.human):
            with self.subTest(principal=actor.subject), self.assertRaises(ExchangeError) as caught:
                self.begin(principal=actor)
            self.assertEqual((caught.exception.status, caught.exception.code),
                             (403, "workload_identity_required"))
            self.assert_no_mutation()

    def test_inventory_identifies_the_owned_resource_without_private_locators(self):
        handle = self.begin()
        report = inspect_mutations(self.service, [self.attempt_id])
        self.assertFalse(report["truncated"])
        self.assertEqual(len(report["attempts"]), 1)
        item = report["attempts"][0]
        self.assertEqual((item["space_id"], item["record_id"], item["attachment_id"], item["attempt_id"]),
                         (self.space_id, self.record["id"], self.attachment, self.attempt_id))
        self.assertEqual(item["mutation_count"], 1)
        public = json.dumps(report)
        for private in (handle.token, handle.object_key, handle.upload_id,
                        "https://storage.example.test/put", "Content-Length"):
            self.assertNotIn(private, public)
        for selection in ([self.attempt_id] * 2, [str(index) for index in range(101)]):
            with self.subTest(selection_size=len(selection)), self.assertRaises(ExchangeError) as caught:
                inspect_mutations(self.service, selection)
            self.assertEqual((caught.exception.status, caught.exception.code),
                             (422, "invalid_attempt_selection"))
        self.assertEqual(self.attempt().mutation_tokens, [handle.token])

    def test_offline_uploading_repair_requires_both_quiescence_assertions_and_is_selected(self):
        abandoned = self.begin()
        other = self.document("repair-isolation-document")
        other_attachment = other["attachments"][0]["id"]
        other_attempt_id = self.transfers.initiate(
            self.space_id, other["id"], other_attachment, self.workload)["attempt_id"]
        sibling = self.begin(record_id=other["id"], attachment_id=other_attachment)
        self.due()
        # Neither inventory nor ordinary workers turn old age into a completed
        # provider operation. The original upload remains blocked.
        for _ in range(2):
            self.assertEqual(tick(self.transfers)["cleaned"], 0)
            self.assertEqual(self.attempt().mutation_tokens, [abandoned.token])
        report = repair_mutations(self.service, [self.attempt_id])
        self.assertTrue(report["attempts"][0]["repairable"])
        self.assertEqual(report["attempts"][0]["action"], "schedule_cleanup")
        self.assertEqual(self.attempt().mutation_tokens, [abandoned.token])
        for writers_stopped, provider_quiesced in ((False, False), (True, False), (False, True)):
            with self.subTest(writers=writers_stopped, provider=provider_quiesced):
                with self.assertRaises(ExchangeError) as caught:
                    repair_mutations(self.service, [self.attempt_id], execute=True,
                                     writers_stopped=writers_stopped, provider_quiesced=provider_quiesced)
                self.assertEqual((caught.exception.status, caught.exception.code),
                                 (409, "storage_quiescence_required"))
                self.assertEqual(self.attempt().mutation_tokens, [abandoned.token])
                self.assertEqual(self.storage.cleaned, [])
        repair_mutations(self.service, [self.attempt_id], execute=True,
                         writers_stopped=True, provider_quiesced=True)
        repaired = self.attempt()
        self.assertEqual((repaired.state, repaired.operation, repaired.mutation_tokens), ("cleanup", "cleanup", []))
        self.assertEqual(self.storage.cleaned, [], "Repair schedules cleanup; it is not provider I/O")
        self.assertEqual(self.attempt(other_attempt_id).mutation_tokens, [sibling.token])
        self.assertEqual(tick(self.transfers)["cleaned"], 1)
        self.assertEqual(self.storage.cleaned, [abandoned.object_key])
        with self.service.sessions() as session:
            self.assertEqual(session.get(Record, self.record["id"]).state, "draft")
            self.assertEqual(session.get(Blob, self.attachment).state, "reserved")
        replacement_id = self.transfers.initiate(*self.args)["attempt_id"]
        self.assertNotEqual(replacement_id, abandoned.attempt_id)
        replacement = self.begin()
        self.assertNotEqual(replacement.object_key, abandoned.object_key)
        self.assertFalse(self.transfers.finish_gateway_put(abandoned))
        self.assertEqual(self.attempt(replacement_id).mutation_tokens, [replacement.token])
        self.assertEqual(self.attempt(other_attempt_id).mutation_tokens, [sibling.token])
        self.assertTrue(self.transfers.finish_gateway_put(replacement))
        self.assertTrue(self.transfers.finish_gateway_put(sibling))

    def test_uploading_repair_does_not_clear_mixed_or_non_gateway_markers(self):
        handle = self.begin()
        with self.service.sessions.begin() as session:
            attempt = session.get(TransferAttempt, self.attempt_id)
            attempt.mutation_tokens = [handle.token, "unresolved-provider-mutation"]
        self.due()
        report = inspect_mutations(self.service, [self.attempt_id])
        self.assertFalse(report["attempts"][0]["repairable"])
        self.assertEqual(report["attempts"][0]["action"], "ineligible")
        with self.assertRaises(ExchangeError) as caught:
            repair_mutations(self.service, [self.attempt_id], execute=True,
                             writers_stopped=True, provider_quiesced=True)
        self.assertEqual((caught.exception.status, caught.exception.code),
                         (409, "attempt_not_repairable"))
        self.assertEqual(self.attempt().mutation_tokens, [handle.token, "unresolved-provider-mutation"])
        self.assertEqual(self.storage.cleaned, [])

    def test_stale_or_foreign_execution_claims_are_denied_before_reservation(self):
        fields = ({"grant_id": "not-granted"}, {"job_id": "job-b"},
                  {"attempt_id": "attempt-b"}, {"component_id": "component-b"},
                  {"epoch": 2}, {"certificate_thumbprint": "b" * 43},
                  {"space_id": "foreign-space"}, {"expires_at": 0})
        for changed in fields:
            actor = replace(self.workload, workload=replace(self.workload.workload, **changed))
            with self.subTest(changed=changed), self.assertRaises(ExchangeError):
                self.begin(principal=actor)
            self.assert_no_mutation()

    def test_current_revocation_and_membership_changes_apply_before_reservation(self):
        with self.service.sessions.begin() as session:
            session.get(WorkloadGrant, self.grant["grant_id"]).expires_at = 0
        with self.assertRaises(ExchangeError):
            self.begin()
        self.assert_no_mutation()
        with self.service.sessions.begin() as session:
            session.get(WorkloadGrant, self.grant["grant_id"]).expires_at = database_time(session) + 1000
        self.service.put_member(self.owner, self.space_id, self.component_id, {
            "subject": "component-a", "roles": ["reader"], "bindings": {"participant": "alice"}})
        with self.assertRaises(ExchangeError):
            self.begin()
        self.assert_no_mutation()
        self.service.put_member(self.owner, self.space_id, self.component_id, {
            "subject": "component-a", "roles": ["reader", "contributor"], "bindings": {"participant": "alice"}})
        self.service.revoke_workload_grants(self.owner, self.space_id,
                                           {"attempt_id": "attempt-a"}, "gateway-current-revoke")
        with self.assertRaises(ExchangeError):
            self.begin()
        self.assert_no_mutation()

    def test_invalid_part_and_record_attachment_binding_never_reserve_a_call(self):
        for number in (0, -1, 2, True, "1", 1.0, None):
            with self.subTest(number=number), self.assertRaises(ExchangeError):
                self.begin(number=number)
            self.assert_no_mutation()
        other = self.document("gateway-binding-document")
        for record_id, attachment_id in (
                ("missing-record", self.attachment),
                (self.record["id"], "missing-attachment"),
                (other["id"], self.attachment),
                (self.record["id"], other["attachments"][0]["id"])):
            with self.subTest(record=record_id, attachment=attachment_id), self.assertRaises(ExchangeError):
                self.begin(record_id=record_id, attachment_id=attachment_id)
            self.assert_no_mutation()

    def test_withdrawn_draft_and_nonuploading_attempt_never_reserve_a_call(self):
        with self.service.sessions.begin() as session:
            session.get(TransferAttempt, self.attempt_id).state = "completing"
        with self.assertRaises(ExchangeError):
            self.begin()
        self.assert_no_mutation()
        with self.service.sessions.begin() as session:
            session.get(TransferAttempt, self.attempt_id).state = "uploading"
            session.get(Record, self.record["id"]).expires_at = 0
        with self.assertRaises(ExchangeError):
            self.begin()
        self.assert_no_mutation()

    def test_upload_handle_must_match_the_reserved_attempt_object_key(self):
        attempt = self.attempt()
        for document in ({}, {"id": ""}, {"id": "foreign-upload", "key": "another-job/object"}):
            with self.service.sessions.begin() as session:
                session.get(TransferAttempt, attempt.id).upload_handle = document
            with self.subTest(document=document), self.assertRaises(ExchangeError):
                self.begin()
            self.assert_no_mutation()


if __name__ == "__main__":
    unittest.main()
