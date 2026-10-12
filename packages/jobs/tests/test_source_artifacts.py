"""Real SQL ownership, descriptor-safe source snapshots and authorized streams."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import delete, select

from hf2l_jobs.application import Manager
from hf2l_jobs.database import create_database
from hf2l_jobs.domain import Error, utcnow
from hf2l_jobs.gateway import GatewayError
from hf2l_jobs.managed_client import ManagedArtifactBroker
from hf2l_jobs.models import Artifact, Job, JobMember, Project, ProvisioningResource
from hf2l_jobs.resources import ResourceError, ResourceLedger
from hf2l_jobs.retention import RetentionService
from hf2l_jobs.source_artifacts import publish_source_artifacts


def manifest_digest(manifest):
    return hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class SourceArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "jobs"
        self.job_root = self.root / "job-a"
        self.source = self.job_root / "source"
        self.source.mkdir(parents=True)
        self.contents = {"plugin.py": b"VALUE = 7\n", "pkg/data.bin": b"source-opaque-bytes", "empty.txt": b""}
        for name, content in self.contents.items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        # Manager private metadata is outside the exact source child.
        (self.job_root / ".source.json").write_text("private source manifest")
        (self.job_root / "host-credential").write_text("must never be exposed")
        self.manifest = {name: hashlib.sha256(content).hexdigest() for name, content in self.contents.items()}
        self.digest = manifest_digest(self.manifest)
        self.logical_bytes = sum(map(len, self.contents.values()))
        self.physical_bytes = self.logical_bytes + 4096
        self.database = create_database("sqlite:///" + self.temp.name + "/jobs.db")
        self.addCleanup(self.database.close)
        with self.database.transaction() as session:
            session.add(Project(id="project", name="Project", quota_disk_bytes=1024**2))
            session.flush()
            for job_id in ("job-a", "job-b"):
                session.add(Job(id=job_id, project_id="project", creator_id="owner", name=job_id,
                    spec_json={}, spec_hash="a" * 64, target_round=1, state="SUCCEEDED",
                    artifacts_expire_at=utcnow() + timedelta(hours=1)))
            session.flush()
            session.add(JobMember(job_id="job-a", principal_id="reader", role="reader"))
        self.ledger = ResourceLedger(self.database)
        self.resource_id = self.ledger.own(job_id="job-a", attempt_id=None, component_id="owner",
            kind="source", external_id=str(self.source), retained=True,
            details={"sha256": self.digest, "logical_bytes": self.logical_bytes, "size_bytes": self.logical_bytes})
        retention = RetentionService(self.database)
        retention.reserve_resource(self.resource_id, "job-a", 64 * 1024)
        retention.settle_resource(self.resource_id, "job-a", self.physical_bytes)
        self.manager = Manager(self.database, cursor_secret="source-artifact-test-signing-key-at-least-32-bytes")

    def publish(self, **changes):
        arguments = dict(job_id="job-a", resource_id=self.resource_id, job_root=self.job_root,
                         manifest=self.manifest, expected_digest=self.digest, max_files=20, max_bytes=1024)
        arguments.update(changes)
        with self.database.transaction() as session:
            return publish_source_artifacts(session, **arguments)

    def rows(self):
        with self.database.transaction() as session:
            return session.scalars(select(Artifact).order_by(Artifact.id)).all()

    def charged_bytes(self):
        with self.database.transaction() as session:
            return session.get(Project, "project").retained_bytes

    def broker(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic source artifact CA")])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
        ca, private = Path(self.temp.name) / "ca.pem", Path(self.temp.name) / "ca.key"
        ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        private.chmod(0o600)
        return ManagedArtifactBroker(self.manager, self.database, None, None, self.root,
            client_ca_certificate=ca, client_ca_key=private, gateway_endpoint="https://gateway.example.invalid",
            service_ca_file=ca, max_bytes=1024)

    def read(self, artifact_id, actor="reader", job_id="job-a"):
        broker = self.broker()
        async def collect():
            async with broker.open_authorized(actor, job_id, artifact_id) as opened:
                return opened.name, b"".join([chunk async for chunk in opened.chunks])
        return asyncio.run(collect())

    def test_publish_verified_per_file_metadata_preserves_physical_storage_charge(self):
        ids = self.publish()
        self.assertEqual(len(ids), 3)
        self.assertEqual(self.charged_bytes(), self.physical_bytes)
        by_path = {row.locator_json["relative_path"]: row for row in self.rows()}
        self.assertEqual(set(by_path), set(self.contents))
        for path, row in by_path.items():
            self.assertEqual(row.kind, "source")
            self.assertIsNone(row.attempt_number)
            self.assertEqual(row.name, Path(path).name)
            self.assertEqual(row.size_bytes, len(self.contents[path]))
            self.assertEqual(row.sha256, self.manifest[path])
            self.assertEqual(row.locator_json, {"kind": "local", "resource_id": self.resource_id, "relative_path": path})
            self.assertIsNotNone(row.expires_at)
        self.assertFalse(any("credential" in row.name or ".source" in row.name for row in self.rows()))

    def test_replay_has_same_ids_timestamps_and_no_second_charge(self):
        ids = self.publish()
        timestamps = {row.id: row.created_at for row in self.rows()}
        self.assertEqual(self.publish(), ids)
        self.assertEqual({row.id: row.created_at for row in self.rows()}, timestamps)
        self.assertEqual(self.charged_bytes(), self.physical_bytes)

    def test_reader_paginates_and_downloads_exact_source_without_locator_leakage(self):
        self.publish()
        items, cursor = [], None
        while True:
            page = self.manager.list_artifacts("reader", "job-a", limit=1, cursor=cursor)
            items.extend(page["items"])
            cursor = page["next_cursor"]
            if cursor is None:
                break
        self.assertEqual({item["source_path"] for item in items}, set(self.contents))
        for item in items:
            self.assertTrue(item["download_available"])
            self.assertNotIn("locator", item)
            self.assertNotIn("storage_key", item)
            self.assertNotIn(self.temp.name, json.dumps(item))
            name, downloaded = self.read(item["id"])
            self.assertEqual(name, Path(item["source_path"]).name)
            self.assertEqual(downloaded, self.contents[item["source_path"]])

    def test_missing_or_revoked_job_reader_and_foreign_job_cannot_download(self):
        identity = self.publish()[0]
        for actor, job_id in (("stranger", "job-a"), ("reader", "job-b")):
            with self.subTest(actor=actor, job_id=job_id), self.assertRaises(Error) as caught:
                self.read(identity, actor, job_id)
            self.assertEqual(caught.exception.status, 404)
        with self.database.transaction() as session:
            session.execute(delete(JobMember).where(JobMember.job_id == "job-a"))
        with self.assertRaises(Error) as caught:
            self.read(identity)
        self.assertEqual(caught.exception.status, 404)

    def test_changed_same_size_source_bytes_fail_download_integrity(self):
        self.publish()
        row = next(row for row in self.rows() if row.name == "plugin.py")
        (self.source / "plugin.py").write_bytes(b"VALUE = 8\n")
        with self.assertRaises(GatewayError) as caught:
            self.read(row.id)
        self.assertEqual(caught.exception.code, "artifact_changed")

    def test_manifest_change_digest_change_and_wrong_file_bytes_publish_nothing(self):
        for arguments in ({"expected_digest": "0" * 64}, {"manifest": {}}, {"max_bytes": 1}, {"max_files": 2}):
            with self.subTest(arguments=arguments), self.assertRaises(ResourceError):
                self.publish(**arguments)
            self.assertEqual(self.rows(), [])
        (self.source / "plugin.py").write_bytes(b"VALUE = 9\n")
        with self.assertRaises(ResourceError):
            self.publish()
        self.assertEqual(self.rows(), [])

    def test_links_and_special_files_fail_before_metadata_publication(self):
        original = self.source / "plugin.py"
        original.unlink()
        for mode in ("symbolic", "hard", "fifo"):
            with self.subTest(mode=mode):
                foreign = Path(self.temp.name) / "outside"
                foreign.write_bytes(self.contents["plugin.py"])
                if mode == "symbolic":
                    original.symlink_to(foreign)
                elif mode == "hard":
                    os.link(foreign, original)
                else:
                    os.mkfifo(original)
                with self.assertRaises(ResourceError):
                    self.publish()
                self.assertEqual(self.rows(), [])
                original.unlink()
                foreign.unlink()

    def test_git_private_paths_and_traversal_in_manifest_fail_closed(self):
        for name in (".git/config", "pkg/.git/objects/a", "../host-credential", "/etc/passwd", "pkg/../plugin.py", "pkg\\file"):
            manifest = {name: "a" * 64}
            with self.subTest(name=name), self.assertRaises(ResourceError):
                self.publish(manifest=manifest, expected_digest=manifest_digest(manifest))
            self.assertEqual(self.rows(), [])

    def test_only_exact_owned_job_source_resource_is_eligible(self):
        with self.database.transaction() as session:
            session.get(ProvisioningResource, self.resource_id).ownership_json = {"job_id": "job-b"}
        with self.assertRaises(ResourceError):
            self.publish()
        with self.database.transaction() as session:
            session.get(ProvisioningResource, self.resource_id).ownership_json = {"job_id": "job-a"}
        for root in (self.root, self.root / "job-b", self.job_root / ".." / "job-a"):
            with self.subTest(root=root), self.assertRaises(ResourceError):
                self.publish(job_root=root)
        with self.database.transaction() as session:
            session.get(ProvisioningResource, self.resource_id).external_id = str(Path(self.temp.name))
        with self.assertRaises(ResourceError):
            self.publish()
        self.assertEqual(self.rows(), [])

    def test_unsettled_released_deleted_or_wrong_charge_cannot_publish(self):
        for change in ({"retention_charge_settled": False}, {"retention_charge_released": True},
                       {"retention_charged_bytes": 1}, {"logical_bytes": 1}, {"sha256": "0" * 64}):
            with self.database.transaction() as session:
                row = session.get(ProvisioningResource, self.resource_id)
                original = dict(row.details_json)
                row.details_json = {**original, **change}
            with self.subTest(change=change), self.assertRaises(ResourceError):
                self.publish()
            with self.database.transaction() as session:
                session.get(ProvisioningResource, self.resource_id).details_json = original
        with self.database.transaction() as session:
            session.get(ProvisioningResource, self.resource_id).state = "cleanup_pending"
        with self.assertRaises(ResourceError):
            self.publish()
        self.assertEqual(self.rows(), [])

    def test_expired_and_purged_job_deny_publication_and_download(self):
        identity = self.publish()[0]
        for field, value in (("artifacts_expire_at", utcnow() - timedelta(seconds=1)), ("purged_at", utcnow())):
            with self.database.transaction() as session:
                setattr(session.get(Job, "job-a"), field, value)
            with self.subTest(field=field), self.assertRaises(ResourceError):
                self.publish()
            with self.assertRaises(Error) as caught:
                self.read(identity)
            self.assertEqual(caught.exception.status, 410)
            with self.database.transaction() as session:
                setattr(session.get(Job, "job-a"), field, utcnow() + timedelta(hours=1) if field == "artifacts_expire_at" else None)

    def test_conflicting_existing_metadata_rolls_back_new_rows(self):
        identities = self.publish()
        with self.database.transaction() as session:
            session.execute(delete(Artifact).where(Artifact.id != identities[-1]))
            session.get(Artifact, identities[-1]).sha256 = "0" * 64
        with self.assertRaises(ResourceError):
            self.publish()
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.charged_bytes(), self.physical_bytes)

    def test_symlink_job_root_cannot_publish_host_source(self):
        linked = Path(self.temp.name) / "linked"
        linked.symlink_to(self.root, target_is_directory=True)
        with self.database.transaction() as session:
            session.get(ProvisioningResource, self.resource_id).external_id = str(linked / "job-a" / "source")
        with self.assertRaises(ResourceError):
            self.publish(job_root=linked / "job-a")
        self.assertEqual(self.rows(), [])

    def test_long_relative_paths_remain_exact_in_reader_metadata(self):
        name = "a" * 180 + "/" + "b" * 180 + "/plugin.py"
        path = self.source / name
        path.parent.mkdir(parents=True)
        path.write_bytes(b"long path source")
        self.contents[name] = path.read_bytes()
        self.manifest[name] = hashlib.sha256(self.contents[name]).hexdigest()
        self.digest = manifest_digest(self.manifest)
        self.logical_bytes = sum(map(len, self.contents.values()))
        with self.database.transaction() as session:
            row = session.get(ProvisioningResource, self.resource_id)
            row.details_json = {**row.details_json, "sha256": self.digest,
                "logical_bytes": self.logical_bytes, "size_bytes": self.logical_bytes}
        self.publish()
        row = next(row for row in self.rows() if row.locator_json["relative_path"] == name)
        view = self.manager.get_artifact("reader", "job-a", row.id)
        self.assertEqual(view["source_path"], name)
        self.assertEqual(view["name"], "plugin.py")
        self.assertEqual(self.read(row.id), ("plugin.py", self.contents[name]))

    def test_outer_transaction_rollback_leaves_no_metadata(self):
        with self.assertRaisesRegex(RuntimeError, "simulated crash"):
            with self.database.transaction() as session:
                publish_source_artifacts(session, job_id="job-a", resource_id=self.resource_id, job_root=self.job_root,
                    manifest=self.manifest, expected_digest=self.digest)
                raise RuntimeError("simulated crash")
        self.assertEqual(self.rows(), [])
        self.assertEqual(len(self.publish()), 3)


if __name__ == "__main__":
    unittest.main()
