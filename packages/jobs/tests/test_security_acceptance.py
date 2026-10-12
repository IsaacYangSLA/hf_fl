"""Security acceptance against real manager transactions and safe file readers.

These tests establish application authorization and collection boundaries.
Actual gVisor/process/network isolation is separately qualified on Linux; a
passing SQL or HTTP test does not qualify a sandbox runtime.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from pydantic import ValidationError

from hf2l_jobs.application import Manager
from hf2l_jobs.collection import CollectionError, SafeCollector
from hf2l_jobs.database import create_database
from hf2l_jobs.domain import Error, JobSpec
from hf2l_jobs import models
from hf2l_jobs.source import SourceApproval, SourceError, SourceRegistry


def valid_spec(name="A private job"):
    return {
        "project_id": "project-a", "name": name,
        "source_id": "source-a", "source_commit": "a" * 40,
        "runtime_image": "public-runtime", "plugin": "untrusted_plugin:factory",
        "target_round": 3, "max_duration_seconds": 3600,
        "participants": [
            {"participant_id": "participant-a", "dataset_binding": "dataset-a", "mode": "external"},
            {"participant_id": "participant-b", "dataset_binding": "dataset-b", "mode": "external"},
        ],
        "components": [{"component_id": "owner", "role": "owner",
                        "resources": {"pool_id": "cpu-pool", "cpu_millicores": 1000,
                                      "memory_bytes": 64 * 1024 * 1024,
                                      "disk_bytes": 64 * 1024 * 1024}}],
    }


class ManagerSecurityAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 9, tzinfo=timezone.utc)
        self.database = create_database("sqlite:///:memory:")
        self.addCleanup(self.database.close)
        self.manager = Manager(self.database, "security-cursor-key-at-least-32-bytes",
                               clock=lambda: self.now)
        with self.database.transaction() as session:
            session.add_all([
                models.Project(id="project-a", name="Project A"),
                models.Project(id="project-b", name="Project B"),
            ])
            session.flush()
            session.add_all([
                models.ProjectMember(project_id="project-a", principal_id="alice", role="submitter"),
                models.ProjectMember(project_id="project-a", principal_id="bob", role="submitter"),
                models.Pool(id="cpu-pool", name="CPU", node_id="node",
                            cpu_millicores=8000, memory_bytes=1024**3,
                            disk_bytes=1024**3, healthy=True,
                            sandbox_profiles=["runsc-cpu-v1"]),
                models.ApprovedSource(id="source-a", project_id="project-a",
                                      url="https://sources.example.test/a.git",
                                      allowed_commits=["a" * 40]),
                models.ParticipantBinding(id="dataset-a", project_id="project-a",
                                          participant_id="participant-a", node_id="participant-node-a",
                                          dataset_label="Approved participant A dataset"),
                models.ParticipantBinding(id="dataset-b", project_id="project-a",
                                          participant_id="participant-b", node_id="participant-node-b",
                                          dataset_label="Approved participant B dataset"),
                models.RuntimeImage(id="public-runtime", digest="sha256:" + "1" * 64),
                models.RuntimeImage(id="private-b-runtime", project_id="project-b",
                                    digest="sha256:" + "2" * 64),
            ])

    def create(self, actor, key, name):
        result = self.manager.create_job(actor, valid_spec(name), key)
        self.now += timedelta(seconds=1)
        return result

    def assert_denied(self, action, status=404):
        with self.assertRaises(Error) as failure:
            action()
        self.assertEqual(failure.exception.status, status)
        return failure.exception

    def test_project_submission_does_not_reveal_another_project_job(self):
        alice = self.create("alice", "a-create", "Alice confidential model")
        bob = self.create("bob", "b-create", "Bob confidential model")
        page = self.manager.list_jobs("alice")
        self.assertEqual(page["total"], 1)
        self.assertEqual(page["counts"], {"queued": 1, "current": 0, "history": 0})
        self.assertEqual([row["id"] for row in page["items"]], [alice["id"]])
        self.assertNotIn(bob["id"], str(page))
        self.assertNotIn("Bob confidential", str(page))
        self.assert_denied(lambda: self.manager.get_job("alice", bob["id"]))
        self.assert_denied(lambda: self.manager.list_members("alice", bob["id"]))

    def test_platform_operator_has_no_implicit_job_content_access(self):
        job = self.create("alice", "operator-case", "Confidential")
        operator = SimpleNamespace(id="platform-user", platform_operator=True)
        self.assertEqual(self.manager.list_jobs(operator)["total"], 0)
        self.assert_denied(lambda: self.manager.get_job(operator, job["id"]))

    def test_acl_precedes_pagination_and_current_counts(self):
        first = self.create("alice", "old-visible", "Visible old")
        self.create("bob", "foreign-middle", "Foreign middle")
        newest = self.create("alice", "new-visible", "Visible newest")
        page = self.manager.list_jobs("alice", filters={"view": "all"}, limit=1)
        self.assertEqual(page["total"], 2)
        self.assertEqual(page["counts"]["queued"], 2)
        self.assertEqual(page["items"][0]["id"], newest["id"])
        cursor = page["next_cursor"]
        self.assertIsNotNone(cursor)
        with self.database.transaction() as session:
            session.delete(session.get(models.Membership, (first["id"], "alice")))
        followup = self.manager.list_jobs("alice", filters={"view": "all"},
                                          limit=1, cursor=cursor)
        self.assertEqual(followup["items"], [])
        self.assertEqual(followup["total"], 1)
        self.assertEqual(followup["counts"]["queued"], 1)
        self.assert_denied(lambda: self.manager.list_jobs(
            "bob", filters={"view": "all"}, limit=1, cursor=cursor), 422)
        self.assert_denied(lambda: self.manager.list_jobs(
            "alice", filters={"view": "history"}, limit=1, cursor=cursor), 422)

    def test_create_replay_respects_revoked_job_membership(self):
        specification = valid_spec("Replay case")
        job = self.manager.create_job("alice", specification, "old-create")
        updated = self.manager.put_member("alice", job["id"], "bob", "admin",
                                          job["version"], "grant-other-admin")
        self.manager.delete_member("bob", job["id"], "alice", updated["version"],
                                   "revoke-original-creator")
        self.assert_denied(lambda: self.manager.get_job("alice", job["id"]))
        self.assert_denied(lambda: self.manager.create_job(
            "alice", specification, "old-create"))

    def test_job_admin_cannot_remove_the_only_effective_admin(self):
        job = self.create("alice", "last-admin", "Last admin")
        for role in ("reader", "operator"):
            with self.subTest(role=role):
                failure = self.assert_denied(lambda: self.manager.put_member(
                    "alice", job["id"], "alice", role, job["version"],
                    "downgrade-" + role), 409)
                self.assertEqual(failure.code, "last_job_admin_required")
        failure = self.assert_denied(lambda: self.manager.delete_member(
            "alice", job["id"], "alice", job["version"], "delete-last-admin"), 409)
        self.assertEqual(failure.code, "last_job_admin_required")

    def test_foreign_project_private_runtime_cannot_be_selected(self):
        specification = valid_spec()
        specification["runtime_image"] = "private-b-runtime"
        self.assert_denied(lambda: self.manager.create_job(
            "alice", specification, "private-image-by-name"), 422)
        specification["runtime_image"] = "sha256:" + "2" * 64
        self.assert_denied(lambda: self.manager.create_job(
            "alice", specification, "private-image-by-digest"), 422)

    def test_inline_credentials_commands_and_space_selectors_are_rejected(self):
        attacks = [
            {"options": {"nested": {"access_token": "literal-token"}}},
            {"options": {"mounts": ["/other/job"]}},
            {"options": {"nested": {"docker-flags": "--privileged"}}},
            {"options": {"command": ["sh", "-c", "arbitrary"]}},
            {"space_id": "foreign-space"},
            {"repository": "/other/job/code"},
            {"components": [{"component_id": "../foreign", "role": "owner",
                              "resources": valid_spec()["components"][0]["resources"]}]},
        ]
        for changes in attacks:
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                JobSpec.model_validate({**valid_spec(), **changes})

    def test_secret_references_are_not_exposed_in_job_metadata(self):
        with self.database.transaction() as session:
            session.add(models.SecretReference(id="private-training-secret",
                                               project_id="project-a"))
        specification = valid_spec()
        specification["secret_refs"] = {"trainer": "private-training-secret"}
        job = self.manager.create_job("alice", specification, "with-private-ref")
        self.assertNotIn("secret_refs", job["spec"])
        self.assertNotIn("private-training-secret", str(self.manager.list_jobs("alice")))
        self.assertNotIn("private-training-secret", str(self.manager.get_job("alice", job["id"])))


    def test_foreign_changes_do_not_affect_authorized_stream_revision(self):
        alice = self.create("alice", "stream-alice", "Visible")
        bob = self.create("bob", "stream-bob", "Inaccessible")
        revision = self.manager.visible_revision("alice")
        self.manager.cancel("bob", bob["id"], bob["version"], "change-foreign")
        self.assertEqual(self.manager.visible_revision("alice"), revision)
        self.manager.cancel("alice", alice["id"], alice["version"], "change-visible")
        self.assertNotEqual(self.manager.visible_revision("alice"), revision)

    def test_historical_artifacts_remain_acl_scoped_and_hide_origin_locators(self):
        alice = self.create("alice", "artifact-alice", "Own history")
        bob = self.create("bob", "artifact-bob", "Foreign history")
        with self.database.transaction() as session:
            for job in (alice, bob):
                row = session.get(models.JobRecord, job["id"])
                row.state = "SUCCEEDED"
                row.terminated_at = self.now
            session.add_all([
                models.Artifact(id="own-artifact", job_id=alice["id"], kind="checkpoint",
                                name="global.bin", size_bytes=12, sha256="a" * 64,
                                storage_key="/private/only-manager-can-read/own",
                                expires_at=self.now - timedelta(seconds=1)),
                models.Artifact(id="foreign-artifact", job_id=bob["id"], kind="checkpoint",
                                name="private-b.bin", size_bytes=12, sha256="b" * 64,
                                storage_key="/private/job-b/checkpoint"),
            ])
        history = self.manager.list_jobs("alice", filters={"view": "history"})
        self.assertEqual(history["total"], 1)
        self.assertEqual(history["counts"]["history"], 1)
        artifacts = self.manager.list_artifacts("alice", alice["id"])
        self.assertNotIn("/private/", str(artifacts))
        self.assertFalse(artifacts["items"][0]["download_available"])
        self.assert_denied(lambda: self.manager.artifact_storage(
            "alice", alice["id"], "own-artifact"), 410)
        self.assert_denied(lambda: self.manager.get_artifact(
            "alice", alice["id"], "foreign-artifact"))
        for operation in (self.manager.list_attempts, self.manager.list_events,
                          self.manager.list_logs, self.manager.list_artifacts):
            with self.subTest(operation=operation.__name__):
                self.assert_denied(lambda: operation("alice", bob["id"]))

    def test_unverified_certificate_headers_cannot_enter_internal_node_routes(self):
        from fastapi.testclient import TestClient
        from hf2l_jobs.api import create_app

        class UnusedAuthenticator:
            def authenticate_node(self, *args, **kwargs):
                raise AssertionError("Unverified headers reached node authentication")

        app = create_app(self.manager, UnusedAuthenticator(), controller=object(),
                         cursor_secret="independent-stream-secret-at-least-32-bytes")
        route = "/internal/jobs/v1/assignments/job-a/attempt-a/owner/1/ack"
        with TestClient(app, base_url="https://testserver") as client:
            for headers in (
                {"Authorization": "Bearer copied-job-token"},
                {"Authorization": "Bearer copied-job-token",
                 "X-Forwarded-Client-Cert": "attacker-certificate"},
                {"Authorization": "Bearer copied-job-token",
                 "X-HF2L-TLS-Thumbprint": "a" * 43},
            ):
                with self.subTest(headers=tuple(headers)):
                    response = client.post(route, headers=headers)
                    self.assertEqual(response.status_code, 401)
                    self.assertEqual(response.json()["error"]["code"],
                                     "verified_node_certificate_required")


    def test_real_mtls_node_callback_enforces_certificate_job_and_current_epoch(self):
        import httpx
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from fastapi.testclient import TestClient
        from sqlalchemy import select
        from hf2l_jobs.api import create_app
        from hf2l_jobs.auth import AuthService
        from hf2l_jobs.broker import BrokerSettings, WorkloadBroker
        from hf2l_jobs.config import OIDCSettings, Settings
        from hf2l_jobs.controller import Controller
        from hf2l_jobs.execution_proxy import start_mtls_server
        from hf2l_jobs.gateway import tls_context
        from test_gateway import certificate_bundle

        job = self.create("alice", "mtls-callback", "Certificate scoped callback")
        with self.database.transaction() as session:
            stored_job = session.get(models.Job, job["id"])
            stored_job.state = "STARTING"
            attempt = session.scalar(select(models.Attempt).where(models.Attempt.job_id == job["id"]))
            attempt.state = "STARTING"
            attempt_id, epoch = attempt.id, attempt.epoch
            stored_job.epoch = epoch
            stored_job.current_attempt = attempt.number
            session.add(models.Allocation(id="node-callback-allocation", job_id=job["id"],
                attempt_id=attempt_id, component_id="owner", pool_id="cpu-pool",
                cpu_millicores=1000, memory_bytes=64 * 1024**2, disk_bytes=256 * 1024**2,
                epoch=epoch, state="RESERVED"))
        controller = Controller(self.database, None, None, clock=lambda: self.now)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = key.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        broker_settings = BrokerSettings(workload_issuer="https://workloads.example.test",
            exchange_audience="exchange-managed", gateway_audience="gateway-managed",
            node_audience="node-managed", public_key=public, private_key=key)
        settings = Settings(database_url="sqlite://", cursor_secret="c" * 32,
            session_secret="s" * 32, broker=broker_settings,
            oidc=OIDCSettings(issuer="https://humans.example.test", client_id="dashboard",
                             redirect_uri="https://manager.example.test/auth/callback"))
        def current(actor):
            return controller.check_assignment(actor.node_id, actor.pool_id, actor.job_id,
                actor.attempt_id, actor.component_id, actor.epoch)
        auth = AuthService(self.database.session_factory, settings, node_grant_validator=current)
        self.addCleanup(auth.provider.client.close)
        app = create_app(self.manager, auth, controller=controller, cursor_secret="c" * 32)
        with tempfile.TemporaryDirectory(prefix="hf2l-security-node-mtls-") as temporary:
            certificates = certificate_bundle(Path(temporary))
            broker = WorkloadBroker(broker_settings)
            token = broker.issue_node(node_id="node", pool_id="cpu-pool", job_id=job["id"],
                attempt_id=attempt_id, component_id="owner", grant_id="node-callback-grant",
                epoch=epoch, certificate_thumbprint=certificates["client"][4],
                scopes=["acknowledge"], resources={"cpu_millicores": 1000,
                    "memory_bytes": 64 * 1024**2, "disk_bytes": 256 * 1024**2})
            server = start_mtls_server(app, certificate=certificates["server"][2],
                key=certificates["server"][3], client_ca=certificates["ca"][2])
            endpoint = "https://127.0.0.1:" + str(server.server_address[1])
            route = "/internal/jobs/v1/assignments/" + job["id"] + "/" + attempt_id + "/owner/" + str(epoch) + "/ack"
            headers = {"Authorization": "Bearer " + token}
            try:
                def connection(identity):
                    certificate = certificates[identity] if identity else None
                    return httpx.Client(verify=tls_context(certificates["ca"][2],
                        certificate=certificate[2] if certificate else None,
                        key=certificate[3] if certificate else None), timeout=5,
                        trust_env=False, follow_redirects=False)
                with connection("client") as client:
                    accepted = client.post(endpoint + route, headers=headers)
                    self.assertEqual(accepted.status_code, 200, accepted.text)
                    self.assertTrue(accepted.json()["accepted"])
                    foreign = route.replace(job["id"], "foreign-job", 1)
                    self.assertEqual(client.post(endpoint + foreign, headers=headers).status_code, 404)
                with self.database.transaction(immediate=False) as session:
                    self.assertTrue(session.get(models.Allocation, "node-callback-allocation").acknowledged)
                with connection("other") as client:
                    spoofed = dict(headers, **{"X-HF2L-TLS-Thumbprint": certificates["client"][4],
                        "X-Forwarded-Client-Cert": certificates["client"][4]})
                    denied = client.post(endpoint + route, headers=spoofed)
                    self.assertEqual(denied.status_code, 401, denied.text)
                with connection(None) as client:
                    with self.assertRaises(httpx.TransportError):
                        client.post(endpoint + route, headers=headers)
                with TestClient(app, base_url="https://testserver") as client:
                    denied = client.post(route, headers=dict(headers,
                        **{"X-HF2L-TLS-Thumbprint": certificates["client"][4]}))
                    self.assertEqual(denied.status_code, 401)
                with self.database.transaction() as session:
                    session.get(models.Job, job["id"]).epoch = epoch + 1
                with connection("client") as client:
                    stale = client.post(endpoint + route, headers=headers)
                    self.assertEqual(stale.status_code, 401, stale.text)
            finally:
                server.shutdown()
                server.server_close()



class SourceSecurityAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hf2l-security-source-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repository = self.root / "approved-repository"
        self.repository.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.email", "synthetic@example.test")
        self.git("config", "user.name", "Synthetic fixture")

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repository), *args],
                              check=True, capture_output=True, text=True).stdout.strip()

    def pin(self):
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "Synthetic approved source")
        commit = self.git("rev-parse", "HEAD")
        approval = SourceApproval("approved", frozenset({"project-a"}),
                                  mirror_path=self.repository, commits=frozenset({commit}))
        return SourceRegistry([approval]), commit

    def test_fetching_materializes_only_blobs_without_running_hooks_or_builds(self):
        marker = self.root / "must-not-exist"
        script = "from pathlib import Path; Path(" + repr(str(marker)) + ").write_text('executed')"
        (self.repository / "setup.py").write_text(script)
        (self.repository / "untrusted_plugin.py").write_text(script)
        (self.repository / ".gitattributes").write_text("*.py filter=evil\n")
        registry, commit = self.pin()
        hook = self.repository / ".git/hooks/post-checkout"
        hook.write_text("#!/bin/sh\ntouch " + str(marker) + "\n")
        hook.chmod(0o700)
        self.git("config", "filter.evil.smudge", "touch " + str(marker))
        destination = self.root / "private-snapshot"
        snapshot = registry.materialize("project-a", "approved", commit, destination)
        self.assertFalse(marker.exists())
        self.assertTrue((destination / "setup.py").is_file())
        self.assertFalse((destination / ".git").exists())
        self.assertFalse((destination / ".gitconfig").exists())
        self.assertEqual(set(snapshot.manifest),
                         {"setup.py", "untrusted_plugin.py", ".gitattributes"})
        self.assertEqual((destination / "setup.py").stat().st_mode & 0o222, 0)

    def test_source_fetch_uses_only_explicit_owned_workspace_and_reports_physical_blocks(self):
        from contextlib import contextmanager
        from unittest.mock import patch
        from hf2l_jobs.source import metadata_peak_bytes, source_physical_bytes
        (self.repository / "nested").mkdir()
        (self.repository / "nested" / "data").write_bytes(b"x")
        registry, commit = self.pin()
        workspace = self.root / "job-owned-fetch"
        workspace.mkdir(mode=0o700)
        original, observed = SourceRegistry._fetch_workspace, []
        @contextmanager
        def checked(approval, parent):
            self.assertEqual(parent, workspace)
            with original(approval, parent) as directory:
                self.assertEqual(directory.parent, workspace)
                observed.append(directory)
                yield directory
        destination = self.root / "private-snapshot"
        with patch.object(SourceRegistry, "_fetch_workspace", side_effect=checked):
            snapshot = registry.materialize("project-a", "approved", commit, destination,
                                            workspace_parent=workspace)
        self.assertTrue(observed)
        self.assertEqual(list(workspace.iterdir()), [])
        self.assertEqual(snapshot.physical_bytes,
                         source_physical_bytes(destination, registry.approvals["approved"]))
        self.assertGreater(snapshot.physical_bytes, snapshot.bytes)
        self.assertLessEqual(snapshot.physical_bytes,
                             registry.approvals["approved"].max_bytes
                             + metadata_peak_bytes(registry.approvals["approved"]))

    def test_source_fetch_rejects_symlink_or_public_workspace_before_object_copy(self):
        (self.repository / "data").write_text("owned source")
        registry, commit = self.pin()
        public = self.root / "public-fetch"
        public.mkdir(mode=0o755)
        public.chmod(0o755)
        link = self.root / "linked-fetch"
        link.symlink_to(public, target_is_directory=True)
        for parent in (public, link):
            with self.subTest(parent=parent.name), self.assertRaises(SourceError):
                registry.materialize("project-a", "approved", commit,
                                     self.root / ("snapshot-" + parent.name), workspace_parent=parent)
        self.assertEqual(list(public.iterdir()), [])

    def test_source_tree_directory_fanout_is_refused_before_staging_mkdir(self):
        from dataclasses import replace
        from unittest.mock import patch
        for index in range(40):
            directory = self.repository.joinpath("branch-" + str(index), *("x" for _ in range(29)))
            directory.mkdir(parents=True)
            (directory / "data").write_bytes(b"bounded")
        registry, commit = self.pin()
        registry.approvals["approved"] = replace(registry.approvals["approved"], max_files=40)
        # Git/object operations happen, but no source tree directory can be made.
        with patch("hf2l_jobs.source.tempfile.TemporaryDirectory",
                   side_effect=AssertionError("Source staging began before tree admission")):
            with self.assertRaisesRegex(SourceError, "tree entries"):
                registry.materialize("project-a", "approved", commit, self.root / "snapshot")
        self.assertFalse((self.root / "snapshot").exists())
        self.assertFalse(list(self.root.glob("hf2l-fetch-*")))

    def test_source_path_depth_and_physical_inventory_links_fail_closed(self):
        from hf2l_jobs.source import source_physical_bytes
        with self.assertRaises(SourceError):
            SourceRegistry._safe_name(("/".join(["x"] * 33)).encode())
        (self.repository / "data").write_text("trusted")
        registry, commit = self.pin()
        unsafe = self.root / "physical-inventory"
        unsafe.mkdir(mode=0o700)
        (unsafe / "data").write_text("cannot have two names")
        os.link(unsafe / "data", unsafe / "alias")
        with self.assertRaises(SourceError):
            source_physical_bytes(unsafe, registry.approvals["approved"])

    def test_git_stdout_sink_streams_bounded_chunks_and_refuses_before_writing_over_limit(self):
        import sys
        count, largest = 0, 0
        def sink(chunk):
            nonlocal count, largest
            count += len(chunk)
            largest = max(largest, len(chunk))
        size = 32 * 1024**2
        program = "import os; chunk=b'x'*65536; [os.write(1,chunk) for _ in range(512)]"
        output = SourceRegistry._bounded_process([sys.executable, "-c", program], dict(os.environ),
            stdout_limit=size, stdout_sink=sink)
        self.assertEqual(output, b"")
        self.assertEqual(count, size)
        self.assertLessEqual(largest, 65536)
        refused = []
        with self.assertRaisesRegex(SourceError, "output exceeds"):
            SourceRegistry._bounded_process([sys.executable, "-c", "import os; os.write(1,b'x'*65536)"],
                dict(os.environ), stdout_limit=1, stdout_sink=refused.append)
        self.assertEqual(refused, [])

    def test_mirror_commit_tree_and_blob_bytes_must_match_the_approved_object_ids(self):
        import zlib
        (self.repository / "data").write_bytes(b"original-content")
        registry, commit = self.pin()
        blob = self.git("rev-parse", commit + ":data")
        tree = self.git("rev-parse", commit + "^{tree}")
        other = subprocess.run(["git", "-C", str(self.repository), "hash-object", "-w", "--stdin"],
            input=b"different-valid-object", check=True, capture_output=True).stdout.decode().strip()
        for kind, object_id in (("commit", commit), ("tree", tree), ("blob", blob)):
            with self.subTest(kind=kind):
                raw = subprocess.run(["git", "-C", str(self.repository), "cat-file", kind, object_id],
                    check=True, capture_output=True).stdout
                changed = (raw + b"\nchanged commit message\n" if kind == "commit" else
                           raw[:-20] + bytes.fromhex(other) if kind == "tree" else b"changed-blob-bytes")
                object_path = self.repository / ".git" / "objects" / object_id[:2] / object_id[2:]
                original = object_path.read_bytes()
                object_path.chmod(0o600)
                try:
                    object_path.write_bytes(zlib.compress(kind.encode() + b" " +
                        str(len(changed)).encode() + b"\0" + changed))
                    with self.assertRaises(SourceError):
                        registry.materialize("project-a", "approved", commit,
                                             self.root / ("tampered-" + kind))
                    self.assertFalse((self.root / ("tampered-" + kind)).exists())
                finally:
                    object_path.write_bytes(original)
                    object_path.chmod(0o444)

    def test_approved_sha256_git_repository_uses_its_bound_object_format(self):
        repository = self.root / "sha256-approved"
        repository.mkdir()
        def git(*args):
            return subprocess.run(["git", "-C", str(repository), *args],
                check=True, capture_output=True, text=True).stdout.strip()
        git("init", "--quiet", "--object-format=sha256")
        git("config", "user.email", "fixture@example.test")
        git("config", "user.name", "Fixture")
        content = b"source pinned with sha256 Git objects"
        (repository / "data").write_bytes(content)
        git("add", "data")
        git("commit", "--quiet", "-m", "Pinned SHA256 source")
        commit = git("rev-parse", "HEAD")
        self.assertEqual(len(commit), 64)
        approval = SourceApproval("sha256-approved", frozenset({"project-a"}),
            mirror_path=repository, commits=frozenset({commit}),
            max_bytes=1024**2, max_files=10, max_git_bytes=1024**2, max_git_files=100)
        snapshot = SourceRegistry([approval]).materialize(
            "project-a", approval.source_id, commit, self.root / "sha256-snapshot")
        self.assertEqual(snapshot.commit, commit)
        self.assertEqual((snapshot.path / "data").read_bytes(), content)
        self.assertEqual(set(snapshot.manifest), {"data"})
        self.assertIsNotNone(snapshot.physical_bytes)
        self.assertFalse((snapshot.path / ".git").exists())

    def test_source_symlinks_and_unapproved_projects_fail_closed(self):
        (self.repository / "link").symlink_to("/other/job/code")
        registry, commit = self.pin()
        with self.assertRaises(SourceError):
            registry.materialize("project-a", "approved", commit, self.root / "unsafe")
        with self.assertRaises(SourceError):
            registry.materialize("project-b", "approved", commit, self.root / "foreign")

    def test_approved_https_host_cannot_resolve_to_private_or_metadata_addresses(self):
        approval = SourceApproval("remote", frozenset({"project-a"}),
                                  url="https://approved.example.test/repo.git",
                                  commits=frozenset({"a" * 40}))
        for address in ("127.0.0.1", "169.254.169.254", "10.1.2.3", "::1"):
            resolver = lambda *args, **kwargs: [(2, 1, 6, "", (address, 443))]
            with self.subTest(address=address), self.assertRaises(SourceError):
                SourceRegistry([approval], allowed_hosts=["approved.example.test"],
                               resolver=resolver)._remote(approval)


    def test_git_stdout_is_refused_before_it_can_fill_manager_memory(self):
        (self.repository / "large.py").write_bytes(b"x" * 65536)
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "Large blob")
        blob = self.git("rev-parse", "HEAD:large.py")
        with self.assertRaisesRegex(SourceError, "output exceeds"):
            SourceRegistry._git(self.repository / ".git", "cat-file", "blob", blob,
                                stdout_limit=1024)

    def test_subprocess_diagnostics_and_time_are_bounded(self):
        import sys
        environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        with self.assertRaisesRegex(SourceError, "diagnostics exceed"):
            SourceRegistry._bounded_process(
                [sys.executable, "-c", "import sys; sys.stderr.write('x' * 65536)"],
                environment, stderr_limit=1024)
        with self.assertRaisesRegex(SourceError, "time limit"):
            SourceRegistry._bounded_process(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                environment, timeout=0.1)

    def test_output_limit_kills_descendant_after_process_leader_exits(self):
        import ctypes
        import signal
        import sys
        import time
        # Adopt the orphan so the regression also reaps every test process.
        library = ctypes.CDLL(None, use_errno=True)
        prior = ctypes.c_int()
        self.assertEqual(library.prctl(37, ctypes.byref(prior), 0, 0, 0), 0)
        self.assertEqual(library.prctl(36, 1, 0, 0, 0), 0)
        pid_file = self.root / "bounded-child.pid"
        child = None
        reaped = False
        try:
            script = (
                "import os,time; from pathlib import Path; "
                "child=os.fork(); "
                "os._exit(0) if child else None; "
                "Path(" + repr(str(pid_file)) + ").write_text(str(os.getpid())); "
                "time.sleep(.15); "
                "os.write(2,b'x'*65536); time.sleep(30)"
            )
            with self.assertRaisesRegex(SourceError, "diagnostics exceed"):
                SourceRegistry._bounded_process([sys.executable, "-c", script],
                    {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, stderr_limit=1024)
            child = int(pid_file.read_text())
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline:
                stopped, status = os.waitpid(child, os.WNOHANG)
                if stopped:
                    reaped = True
                    child = None
                    self.assertTrue(os.WIFSIGNALED(status))
                    self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
                    break
                time.sleep(.01)
            else:
                self.fail("A descendant survived the bounded process failure")
        finally:
            if not reaped and child is None and pid_file.exists():
                # No-op if already reaped; clean up even when an assertion fails.
                possible = int(pid_file.read_text())
                try:
                    os.kill(possible, signal.SIGKILL)
                    os.waitpid(possible, 0)
                except (ProcessLookupError, ChildProcessError):
                    pass
            elif child is not None:
                try:
                    os.kill(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(child, 0)
            library.prctl(36, prior.value, 0, 0, 0)

    def test_trusted_mirror_objects_are_bounded_before_snapshot_creation(self):
        (self.repository / "large-object.bin").write_bytes(os.urandom(128 * 1024))
        registry, commit = self.pin()
        approval = SourceApproval("bounded", frozenset({"project-a"}),
                                  mirror_path=self.repository, commits=frozenset({commit}),
                                  max_git_bytes=64 * 1024)
        destination = self.root / "must-not-materialize"
        with self.assertRaisesRegex(SourceError, "object bytes/files"):
            SourceRegistry([approval]).materialize(
                "project-a", "bounded", commit, destination)
        self.assertFalse(destination.exists())

    @unittest.skipUnless(os.environ.get("HF2L_TEST_SOURCE_QUOTAS") == "1",
                         "Explicit privileged Linux source-workspace qualification")
    def test_https_fetch_workspace_has_real_byte_quota_and_confirmed_cleanup(self):
        # This proof writes only an 8MiB task-owned tmpfs. It tests kernel ENOSPC,
        # not an accounting counter or a mocked successful mount command.
        import errno
        approval = SourceApproval("remote", frozenset({"project-a"}),
                                  url="https://approved.example.test/repository.git",
                                  commits=frozenset({"a" * 40}), max_git_bytes=8 * 1024**2)
        workspace = None
        with SourceRegistry._fetch_workspace(approval, self.root) as directory:
            workspace = directory
            information = os.statvfs(directory)
            self.assertLessEqual(information.f_blocks * information.f_frsize, 8 * 1024**2)
            with (directory / "pack-limit-proof").open("wb") as output:
                with self.assertRaises(OSError) as failure:
                    for _ in range(9):
                        output.write(b"x" * 1024**2)
                        output.flush()
                self.assertEqual(failure.exception.errno, errno.ENOSPC)
        self.assertFalse(workspace.exists())


class CollectionSecurityAcceptanceTests(unittest.TestCase):
    def test_cross_job_file_links_and_traversal_are_never_collected(self):
        with tempfile.TemporaryDirectory(prefix="hf2l-security-collection-") as temporary:
            parent = Path(temporary)
            job_a, job_b = parent / "job-a", parent / "job-b"
            job_a.mkdir()
            job_b.mkdir()
            private = job_b / "private-code.py"
            private.write_bytes(b"job B confidential code")
            (job_a / "symlink").symlink_to(private)
            os.link(private, job_a / "hardlink")
            with SafeCollector(job_a) as collector:
                for attack in ("../job-b/private-code.py", str(private), "symlink", "hardlink"):
                    with self.subTest(attack=attack), self.assertRaises(CollectionError):
                        collector.read(attack)
                with self.assertRaises(CollectionError):
                    collector.collect()

    def test_collection_root_cannot_use_a_symlink_in_an_ancestor(self):
        with tempfile.TemporaryDirectory(prefix="hf2l-security-root-") as temporary:
            root = Path(temporary)
            (root / "job-b").mkdir()
            (root / "foreign").symlink_to(root / "job-b", target_is_directory=True)
            with self.assertRaises(CollectionError):
                SafeCollector(root / "foreign")

    def test_secret_values_are_redacted_before_logs_and_events_leave_component(self):
        with tempfile.TemporaryDirectory(prefix="hf2l-security-redaction-") as temporary:
            root = Path(temporary)
            secret = "synthetic-resolved-job-secret"
            (root / "log").write_text("training output: " + secret)
            (root / "events").write_text(
                '{"message":"' + secret + '","access_token":"do-not-retain","metric":0.5}\n')
            with SafeCollector(root, secret_values=[secret]) as collector:
                self.assertNotIn(secret, collector.logs("log"))
                events = collector.events("events")
                self.assertEqual(events, ({"message": "[REDACTED]", "metric": 0.5},))


if __name__ == "__main__":
    unittest.main()
