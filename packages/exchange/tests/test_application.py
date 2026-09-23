"""Command-level invariants, without HTTP, identity providers, or object stores."""
import hashlib
import tempfile
import unittest
from pathlib import Path
from sqlalchemy import select

from hf2l_exchange.application import Service
from hf2l_exchange.config import AuthSettings, DatabaseSettings, Settings
from hf2l_exchange.domain import Error, Principal
from hf2l_exchange.models import Base, Coordination, Record, Reference, Space, TransferAttempt, database_time


class ApplicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        settings = Settings(database=DatabaseSettings(url='sqlite:///' + str(Path(self.temp.name) / 'app.db')),
                            auth=AuthSettings(admin_subject='root'))
        self.service = Service(settings)
        Base.metadata.create_all(self.service.engine)
        self.addCleanup(self.service.engine.dispose)
        self.admin = Principal('root', 'root', True)
        self.space = self.service.create_space(self.admin, {'name': 'documents'}, 'space')['id']
        self.author = self.member('author', ['contributor'])
        self.reader = self.member('reader', ['reader'])
        self.publisher = self.member('publisher', ['publisher'])
        self.admin_only = self.member('admin-only', ['admin'])
        self.type = self.service.register_type(self.admin, self.space, 'document', {'schema': {'type': 'object'}}, 'schema')
        self.counter = 0

    def key(self):
        self.counter += 1
        return str(self.counter)

    def member(self, name, roles, bindings=None):
        self.service.put_member(self.admin, self.space, name, {'roles': roles, 'bindings': bindings or {}})
        return Principal(name, name)

    def record(self, principal=None, metadata=None, revision=None, publish=True):
        principal = principal or self.author
        revision = revision or self.type
        record = self.service.create_record(principal, self.space,
            {'kind': revision['kind'], 'schema_revision_id': revision['id'], 'metadata': metadata or {}}, self.key())
        if publish:
            record = self.service.publish_record(principal, self.space, record['id'], self.key())
        return record

    def error(self, code, fn, *args, **kwargs):
        with self.assertRaises(Error) as caught:
            fn(*args, **kwargs)
        self.assertEqual(code, caught.exception.code)

    def test_generic_metadata_only_and_revision_pinning(self):
        self.error('invalid_json', self.record, metadata={'value': float('nan')})
        old = self.record(metadata={'text': 'old'}, publish=False)
        new = self.service.register_type(self.admin, self.space, 'document',
            {'schema': {'type': 'object', 'required': ['new_field']}}, self.key())
        published = self.service.publish_record(self.author, self.space, old['id'], self.key())
        self.assertEqual(old['schema_revision_id'], published['schema_revision_id'])
        self.error('metadata_schema_mismatch', self.record, revision=new)
        ref = self.service.put_reference(self.publisher, self.space, 'main', {'record_id': old['id']}, '*', self.key())
        self.assertEqual('1', ref['token'])
        self.assertEqual(old['id'], self.service.get_reference(self.reader, self.space, 'main')['record_id'])

    def test_current_policy_membership_and_admin_data_separation(self):
        draft = self.record(publish=False)
        self.service.put_policy(self.admin, self.space, 'document', {'publish_roles': ['publisher'], 'visibility': 'private'})
        self.error('role_required', self.service.publish_record, self.author, self.space, draft['id'], self.key())
        record = self.record(principal=self.publisher)
        self.error('record_not_found', self.service.get_record, self.reader, self.space, record['id'])
        self.error('record_not_found', self.service.get_record, self.admin_only, self.space, record['id'])
        self.assertEqual(record['id'], self.service.get_record(self.publisher, self.space, record['id'])['id'])
        cancellation = self.service.withdraw_record(self.admin_only, self.space, draft['id'])
        self.assertEqual({'id', 'state'}, set(cancellation))
        self.service.put_policy(self.admin, self.space, 'document', {'publish_roles': ['publisher'], 'visibility': 'shared'})
        self.assertEqual(record['id'], self.service.get_record(self.reader, self.space, record['id'])['id'])
        self.service.put_member(self.admin, self.space, self.reader.id, {'roles': []})
        self.error('space_not_found', self.service.get_record, self.reader, self.space, record['id'])

    def test_metadata_budget_retained_until_explicit_purge(self):
        with self.service.sessions.begin() as session:
            space = session.get(Space, self.space)
            space.quota_records = 1
            space.quota_metadata_bytes = 16
        record = self.record(metadata={'x': 'y'})
        self.service.withdraw_record(self.author, self.space, record['id'])
        self.error('metadata_quota_exceeded', self.record)
        self.service.purge_record(self.admin_only, self.space, record['id'])
        self.record()
        self.assertEqual(1, self.service.get_space(self.admin, self.space)['record_count'])

    def test_coordination_cas_fencing_and_completion_replay(self):
        first, data, result = self.record(), self.record(), self.record()
        self.service.put_reference(self.publisher, self.space, 'latest', {'record_id': first['id']}, '*', self.key())
        body = {'reference': 'latest', 'expected_token': '1', 'input_record_ids': [data['id']]}
        one = self.service.acquire(self.publisher, self.space, body, 'job-one')
        self.assertEqual(one['id'], self.service.acquire(self.publisher, self.space, body, 'job-one')['id'])
        self.error('acquisition_busy', self.service.acquire, self.publisher, self.space, body, 'job-two')
        self.error('acquisition_active', self.service.put_reference, self.publisher, self.space, 'latest',
                   {'record_id': result['id']}, '1', self.key())
        self.error('record_in_active_acquisition', self.service.withdraw_record, self.author, self.space, data['id'])
        with self.service.sessions.begin() as session:
            session.get(Coordination, one['id']).lease_until = database_time(session) - 1
        two = self.service.acquire(self.publisher, self.space, body, 'job-two')
        self.assertGreater(two['fence'], one['fence'])
        self.error('acquisition_not_active', self.service.complete, self.publisher, self.space, one['id'],
                   {'fence': one['fence'], 'result_record_id': result['id']}, self.key())
        completion = {'fence': two['fence'], 'result_record_id': result['id']}
        done = self.service.complete(self.publisher, self.space, two['id'], completion, self.key())
        self.assertEqual('completed', done['state'])
        self.assertEqual(done, self.service.complete(self.publisher, self.space, two['id'], completion, self.key()))
        self.assertEqual('2', self.service.get_reference(self.reader, self.space, 'latest')['token'])

    def test_path_collisions_and_cancel_without_upload_releases_bytes(self):
        attachment = {'path': 'folder', 'size': 1, 'sha256': hashlib.sha256(b'x').hexdigest()}
        body = {'kind': 'document', 'schema_revision_id': self.type['id'], 'metadata': {},
                'attachments': [attachment, dict(attachment, path='FOLDER/file')]}
        self.error('duplicate_attachment_path', self.service.create_record, self.author, self.space, body, self.key())
        body['attachments'] = [attachment]
        record = self.service.create_record(self.author, self.space, body, self.key())
        self.assertEqual(1, self.service.get_space(self.admin, self.space)['allocated'])
        self.service.withdraw_record(self.author, self.space, record['id'])
        space = self.service.get_space(self.admin, self.space)
        self.assertEqual((0, 0), (space['allocated'], space['reclaiming']))
        self.service.purge_record(self.admin, self.space, record['id'])

    def test_event_visibility_and_retention_floor(self):
        self.record(metadata={'visible': True})
        self.service.put_policy(self.admin, self.space, 'document', {'visibility': 'private'})
        self.assertEqual([], self.service.events(self.reader, self.space)['items'])
        self.assertTrue(self.service.events(self.publisher, self.space)['items'])
        with self.service.sessions.begin() as session:
            session.get(Space, self.space).event_floor = 10
        self.error('event_cursor_expired', self.service.events, self.reader, self.space)

    def test_purge_preserves_uncertain_mutation_even_if_marked_cleaned(self):
        attachment = {'path': 'content', 'size': 1, 'sha256': hashlib.sha256(b'x').hexdigest()}
        record = self.service.create_record(self.author, self.space,
            {'kind': 'document', 'schema_revision_id': self.type['id'], 'metadata': {},
             'attachments': [attachment]}, self.key())
        # Cancellation without upload safely marks the reserved blob cleaned.
        self.service.withdraw_record(self.author, self.space, record['id'])
        blob_id = record['attachments'][0]['id']
        with self.service.sessions.begin() as session:
            session.add(TransferAttempt(id='uncertain', blob_id=blob_id, object_key='attempt-owned',
                        state='cleaned', mutation_tokens=['unsettled-provider-call']))
        before = self.service.get_space(self.admin, self.space)
        self.error('cleanup_pending', self.service.purge_record, self.admin_only, self.space, record['id'])
        with self.service.read_sessions.begin() as session:
            self.assertIsNotNone(session.get(Record, record['id']))
            self.assertEqual(['unsettled-provider-call'], session.get(TransferAttempt, 'uncertain').mutation_tokens)
        self.assertEqual(before['record_count'], self.service.get_space(self.admin, self.space)['record_count'])
        # Only independently settling the marker permits reclamation of metadata.
        with self.service.sessions.begin() as session:
            session.get(TransferAttempt, 'uncertain').mutation_tokens = []
        self.service.purge_record(self.admin_only, self.space, record['id'])
        self.assertEqual(before['record_count'] - 1, self.service.get_space(self.admin, self.space)['record_count'])

    def test_reference_names_are_route_safe(self):
        record = self.record()
        for name in ('nested/name', 'with space', '?query', '', 'x' * 129):
            self.error('invalid_reference_name', self.service.put_reference,
                       self.publisher, self.space, name, {'record_id': record['id']}, '*', self.key())
        for name in ('main', 'latest', 'release_2026-09.1'):
            result = self.service.put_reference(self.publisher, self.space, name,
                                                {'record_id': record['id']}, '*', self.key())
            self.assertEqual(name, result['name'])

    def test_admin_quota_updates_preserve_current_usage(self):
        original = self.service.get_space(self.admin, self.space)
        updated = self.service.update_space_limits(self.admin_only, self.space, {'quota_records': 1})
        self.assertEqual(original['generation'] + 1, updated['generation'])
        one = self.record()
        self.error('metadata_quota_exceeded', self.record)
        self.error('role_required', self.service.update_space_limits,
                   self.reader, self.space, {'quota_records': 2})
        self.service.update_space_limits(self.admin_only, self.space, {'quota_records': 2})
        self.record()
        self.error('quota_below_current_usage', self.service.update_space_limits,
                   self.admin_only, self.space, {'quota_records': 1})
        self.error('invalid_quota_fields', self.service.update_space_limits,
                   self.admin_only, self.space, {'profile': 'fedavg.v1'})
        self.error('invalid_quota', self.service.update_space_limits,
                   self.admin_only, self.space, {'quota_bytes': 2**63})
        self.service.update_space_limits(self.admin_only, self.space, {'quota_records': 3})
        attachment = {'path': 'content', 'size': 10, 'sha256': hashlib.sha256(b'x' * 10).hexdigest()}
        record = self.service.create_record(self.author, self.space,
            {'kind': 'document', 'schema_revision_id': self.type['id'], 'metadata': {},
             'attachments': [attachment]}, self.key())
        for field in ('quota_bytes', 'principal_quota_bytes'):
            self.error('quota_below_current_usage', self.service.update_space_limits,
                       self.admin_only, self.space, {field: 9})
        self.service.withdraw_record(self.author, self.space, record['id'])
        self.service.update_space_limits(self.admin_only, self.space,
                                          {'quota_bytes': 9, 'principal_quota_bytes': 9})
        self.assertEqual(3, self.service.get_space(self.admin, self.space)['record_count'])

    def test_withdrawal_tombstones_respect_current_policy_and_survive_purge(self):
        shared = self.record(metadata={'secret': 'never include in event'})
        self.service.withdraw_record(self.author, self.space, shared['id'])
        feed = self.service.events(self.reader, self.space)['items']
        self.assertEqual(1, len(feed))
        self.assertEqual(shared['id'], feed[0]['record_id'])
        self.assertEqual({'state': 'withdrawn'}, feed[0]['payload'])
        self.error('record_not_found', self.service.get_record, self.reader, self.space, shared['id'])
        self.service.purge_record(self.admin_only, self.space, shared['id'])
        self.assertEqual(feed, self.service.events(self.reader, self.space)['items'])
        # Current kind policy still authorizes tombstones after metadata reclamation.
        self.service.put_policy(self.admin, self.space, 'document', {'visibility': 'private'})
        self.assertEqual([], self.service.events(self.reader, self.space)['items'])
        self.assertEqual(feed, self.service.events(self.publisher, self.space)['items'])
        private = self.record(metadata={'private': 'content'})
        draft = self.record(publish=False)
        self.service.withdraw_record(self.author, self.space, private['id'])
        self.service.withdraw_record(self.author, self.space, draft['id'])
        self.service.put_policy(self.admin, self.space, 'document', {'visibility': 'shared'})
        feed = self.service.events(self.reader, self.space)['items']
        self.assertEqual({shared['id'], private['id']}, {event['record_id'] for event in feed})
        self.assertTrue(all(event['payload'] == {'state': 'withdrawn'} for event in feed))
        self.service.put_member(self.admin, self.space, self.reader.id, {'roles': []})
        self.error('space_not_found', self.service.events, self.reader, self.space)

    def test_fedavg_profile_cannot_be_bypassed(self):
        self.space = self.service.create_space(self.admin, {'name': 'fedavg', 'profile': 'fedavg.v1'}, 'fedavg')['id']
        self.publisher = self.member('publisher', ['publisher'])
        alice = self.member('alice', ['contributor'], {'participant': 'A'})
        bob = self.member('bob', ['contributor'], {'participant': 'B'})
        global_type = self.service.register_type(self.admin, self.space, 'model.global', {'schema': {'type': 'object'}}, self.key())
        update_type = self.service.register_type(self.admin, self.space, 'training.update', {'schema': {'type': 'object'}}, self.key())
        initial = self.record(self.publisher, {'inputs': []}, global_type)
        self.service.put_reference(self.publisher, self.space, 'main', {'record_id': initial['id']}, '*', self.key())
        a = self.record(alice, {'base_record_id': initial['id'], 'sample_count': 1}, update_type)
        self.error('insufficient_participants', self.service.acquire, self.publisher, self.space,
                   {'reference': 'main', 'expected_token': '1'}, self.key())
        b = self.record(bob, {'base_record_id': initial['id'], 'sample_count': 1}, update_type)
        claim = self.service.acquire(self.publisher, self.space, {'reference': 'main', 'expected_token': '1'}, self.key())
        output = self.record(self.publisher, {'base_record_id': initial['id'], 'inputs': [a['id'], b['id']]}, global_type)
        self.error('acquisition_active', self.service.put_reference, self.publisher, self.space, 'main',
                   {'record_id': output['id']}, '1', self.key())
        self.error('profile_policy_conflict', self.service.put_policy, self.admin, self.space, 'model.global',
                   {'publish_roles': ['contributor'], 'visibility': 'private'})
        done = self.service.complete(self.publisher, self.space, claim['id'],
                    {'fence': claim['fence'], 'result_record_id': output['id']}, self.key())
        self.assertEqual('completed', done['state'])
        self.error('coordination_required', self.service.put_reference, self.publisher, self.space, 'main',
                   {'record_id': output['id']}, '2', self.key())


if __name__ == '__main__':
    unittest.main()
