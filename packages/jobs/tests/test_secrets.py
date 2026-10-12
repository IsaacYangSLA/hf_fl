"""Private secret material remains outside job metadata, source and logs."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
from threading import Barrier
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pydantic import ValidationError

from hf2l_jobs.collection import SafeCollector
from hf2l_jobs.database import create_database
from hf2l_jobs.domain import JobSpec
from hf2l_jobs.models import Project, SecretReference
from hf2l_jobs.resources import stable_key
from hf2l_jobs.secrets import (
    ApprovedSecretReference, SecretError, SecretResolver, read_secret_manifest,
)


class SecretResolverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hf2l-secret-tests-")
        self.root = Path(self.temporary.name)
        self.material = self.root / "operator-material"
        self.material.mkdir(mode=0o700)
        self.source = self.material / "plugin-license"
        self.source.write_text("opaque-private-license-value\n")
        self.source.chmod(0o600)
        # Each concurrent resolver call needs its own database connection.
        # An in-memory StaticPool would share one transaction across both threads.
        self.database = create_database(f"sqlite:///{self.root / 'secrets.sqlite3'}")
        with self.database.transaction() as session:
            session.add_all([Project(id="project-a", name="A"), Project(id="project-b", name="B")])
            session.flush()
            session.add(SecretReference(id="license-reference", project_id="project-a",
                                        reference=str(self.source), enabled=True))
        self.catalog = {"license-reference": {
            "project_id": "project-a", "path": str(self.source), "roles": ["owner"],
            "option_names": ["license_key"], "purpose": "plugin_option",
        }}
        self.resolver = SecretResolver(self.database, self.root / "deliveries", self.catalog)
        self.spec = self.make_spec()
        self.job = SimpleNamespace(id="job-a", project_id="project-a", spec_json=self.spec.to_dict(),
                                   spec_hash=self.spec.digest, epoch=1, state="PROVISIONING")
        self.attempt = SimpleNamespace(id="attempt-1", job_id="job-a", epoch=1)
        self.owner = self.spec.components[0]

    def tearDown(self):
        self.database.close()
        self.temporary.cleanup()

    def make_spec(self, *, project_id="project-a", options=None, secret_refs=None, participant=False, build=False):
        resources = dict(pool_id="cpu", cpu_millicores=1000, memory_bytes=1024**3, disk_bytes=1024**3)
        components = [dict(component_id="owner", role="owner", resources=resources)]
        participants = []
        if participant:
            components.append(dict(component_id="alice-client", role="participant", participant_id="alice",
                                   resources=resources))
            participants.append(dict(participant_id="alice", dataset_binding="synthetic", mode="managed",
                                     component_id="alice-client"))
        if build:
            components.append(dict(component_id="build", role="build", resources=resources))
        return JobSpec(project_id=project_id, name="Training", source_id="source",
                       source_commit="a" * 40, runtime_image="approved-image", plugin="plugin",
                       options=options or {}, secret_refs=secret_refs if secret_refs is not None else {"license_key": "license-reference"},
                       participants=participants, components=components, target_round=2, max_duration_seconds=300)

    def bind_spec(self, spec):
        self.spec = spec
        self.job.project_id = spec.project_id
        self.job.spec_json = spec.to_dict()
        self.job.spec_hash = spec.digest
        self.owner = spec.components[0]

    def test_config_accepts_only_declared_secrets_operational_section(self):
        from hf2l_jobs.config import Settings
        config_path = self.root / "operational.json"
        config_path.write_text(json.dumps({"secrets": {"references": self.catalog}}))
        with patch.dict(os.environ, {"JOBS_OPERATIONAL_CONFIG_FILE": str(config_path)}, clear=True):
            settings = Settings.from_env(component="controller")
        self.assertEqual(settings.extra["secrets"]["references"], self.catalog)
        config_path.write_text(json.dumps({"unapproved_secret_url": "https://attacker.invalid"}))
        with patch.dict(os.environ, {"JOBS_OPERATIONAL_CONFIG_FILE": str(config_path)}, clear=True):
            with self.assertRaises(ValueError):
                Settings.from_env(component="controller")

    def test_planning_validates_approval_without_reading_or_materializing(self):
        self.source.unlink()
        planned = self.resolver.planned(self.job, self.attempt, self.owner)
        self.assertEqual(planned.option_names, ("license_key",))
        self.assertEqual(planned.redaction_values, ())
        self.assertEqual(planned.path, self.resolver.root / "job-a" / "attempt-1" / "owner" / "1" / "secrets.json")
        self.assertEqual(self.resolver.plan_path(self.job, self.attempt, self.owner), planned.path)
        self.assertFalse(self.resolver.root.exists())
        self.bind_spec(self.make_spec(participant=True, build=True))
        for component in self.spec.components[1:]:
            self.assertIsNone(self.resolver.planned(self.job, self.attempt, component).path)
        with self.database.transaction() as session:
            session.get(SecretReference, "license-reference").enabled = False
        with self.assertRaises(SecretError):
            self.resolver.planned(self.job, self.attempt, self.owner)

    def external_spec(self, *participant_ids):
        document = self.make_spec().to_dict()
        document["participants"] = [
            dict(participant_id=identifier, dataset_binding="synthetic", mode="external")
            for identifier in participant_ids
        ]
        return JobSpec.model_validate(document)

    @staticmethod
    def external_component(participant_id):
        return SimpleNamespace(component_id="participant-" + stable_key(participant_id)[:40],
                               role="participant", participant_id=participant_id)

    def external_resolver(self, *, component_ids=()):
        catalog = {"license-reference": dict(self.catalog["license-reference"],
                   roles=["participant"], component_ids=list(component_ids))}
        return SecretResolver(self.database, self.root / "external-deliveries", catalog)

    def test_external_participant_plan_reads_only_current_approval_metadata(self):
        self.bind_spec(self.external_spec("alice"))
        resolver = self.external_resolver()
        self.source.unlink()
        self.assertTrue(resolver.validate_spec(self.spec))
        with patch("hf2l_jobs.secrets._private_file", side_effect=AssertionError("secret bytes read")):
            plan = resolver.planned(self.job, self.attempt, self.external_component("alice"))
        self.assertEqual(plan.option_names, ("license_key",))
        self.assertEqual(plan.redaction_values, ())
        self.assertEqual(plan.path, resolver.root / "job-a" / "attempt-1"
                         / self.external_component("alice").component_id / "1" / "secrets.json")
        self.assertFalse(resolver.root.exists())
        self.assertNotIn("opaque-private-license-value", repr(plan))
        self.assertNotIn(str(self.source), json.dumps(self.job.spec_json))
        self.assertEqual(resolver.planned(self.job, self.attempt, self.owner).option_names, ())

    def test_external_participant_identity_cannot_be_forged(self):
        self.bind_spec(self.external_spec("alice"))
        resolver = self.external_resolver()
        expected = self.external_component("alice")
        for component in (
            self.external_component("bob"),
            SimpleNamespace(component_id="alice-client", role="participant", participant_id="alice"),
            SimpleNamespace(component_id=expected.component_id, role="owner", participant_id="alice"),
            SimpleNamespace(component_id=expected.component_id, role="participant", participant_id="bob"),
            SimpleNamespace(component_id=expected.component_id, role="participant", participant_id=None),
        ):
            with self.subTest(component=component), self.assertRaises(SecretError):
                resolver.planned(self.job, self.attempt, component)
        self.bind_spec(self.make_spec(participant=True))
        with self.assertRaises(SecretError):
            resolver.planned(self.job, self.attempt, expected)
        self.assertEqual(resolver.planned(self.job, self.attempt, self.spec.components[1]).option_names,
                         ("license_key",))

    def test_external_component_approval_scope_remains_exact(self):
        self.bind_spec(self.external_spec("alice", "bob"))
        resolver = self.external_resolver(component_ids=(self.external_component("alice").component_id,))
        self.assertEqual(resolver.planned(self.job, self.attempt, self.external_component("alice")).option_names,
                         ("license_key",))
        other = resolver.planned(self.job, self.attempt, self.external_component("bob"))
        self.assertEqual(other.option_names, ())
        self.assertIsNone(other.path)
        unassigned = self.external_resolver(component_ids=(self.external_component("charlie").component_id,))
        with self.assertRaises(SecretError):
            unassigned.validate_spec(self.spec)

    def test_external_plan_requires_current_job_attempt_and_project(self):
        self.bind_spec(self.external_spec("alice"))
        resolver = self.external_resolver()
        target = self.external_component("alice")
        for owner, field, value in (
            (self.job, "project_id", "project-b"), (self.job, "spec_hash", "f" * 64),
            (self.job, "epoch", 2), (self.job, "state", "CANCELLED"),
            (self.attempt, "job_id", "foreign-job"), (self.attempt, "epoch", 2),
        ):
            original = getattr(owner, field)
            setattr(owner, field, value)
            try:
                with self.subTest(field=field, value=value), self.assertRaises(SecretError):
                    resolver.planned(self.job, self.attempt, target)
            finally:
                setattr(owner, field, original)
        for field, value in (("enabled", False), ("project_id", "project-b"),
                             ("reference", "/foreign/private-reference")):
            with self.database.transaction() as session:
                row = session.get(SecretReference, "license-reference")
                original = getattr(row, field)
                setattr(row, field, value)
            try:
                with self.subTest(field=field), self.assertRaises(SecretError):
                    resolver.planned(self.job, self.attempt, target)
            finally:
                with self.database.transaction() as session:
                    setattr(session.get(SecretReference, "license-reference"), field, original)
        self.assertFalse(resolver.root.exists())

    def test_external_canonical_id_cannot_collide_with_managed_component(self):
        spec = self.external_spec("alice")
        target = self.external_component("alice")
        document = spec.to_dict()
        document["components"][0]["component_id"] = target.component_id
        resolver = self.external_resolver()
        with patch("hf2l_jobs.secrets._private_file", side_effect=AssertionError("secret bytes read")):
            with self.assertRaisesRegex(ValidationError, "reserved external participant identity"):
                JobSpec.model_validate(document)

            # The resolver also refuses an invalid in-memory object that bypassed admission.
            unchecked = spec.model_copy(update={"components": (
                spec.components[0].model_copy(update={"component_id": target.component_id}),
            )})
            with self.assertRaisesRegex(SecretError, "conflicts with its immutable job"):
                resolver.validate_spec(unchecked)

            self.job.spec_json = document
            for component in (unchecked.components[0], target):
                with self.subTest(component=component.component_id):
                    with self.assertRaisesRegex(ValidationError, "reserved external participant identity"):
                        resolver.planned(self.job, self.attempt, component)
        self.assertFalse(resolver.root.exists())
        self.assertFalse(self.resolver.root.exists())

    def test_materialized_manifest_matches_reserved_plan(self):
        planned = self.resolver.planned(self.job, self.attempt, self.owner)
        resolved = self.resolver.resolve(self.job, self.attempt, self.owner)
        self.assertEqual(planned.path, resolved.path)
        self.assertEqual(planned.option_names, resolved.option_names)

    def test_only_reference_ids_enter_job_metadata(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            resolved = self.resolver.resolve(self.job, self.attempt, self.owner)
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn("opaque-private-license-value", repr(resolved))
        self.assertNotIn("opaque-private-license-value", repr(self.resolver.approvals))
        self.assertNotIn("opaque-private-license-value", json.dumps(self.job.spec_json))
        self.assertNotIn(str(self.source), json.dumps(self.job.spec_json))
        self.assertEqual(resolved.redaction_values, ("opaque-private-license-value",))
        self.assertEqual(resolved.option_names, ("license_key",))
        manifest = read_secret_manifest(resolved.privatepath, resolved)
        self.assertEqual(manifest["options"], {"license_key": "opaque-private-license-value"})
        self.assertEqual(manifest["references"], {"license_key": "license-reference"})
        self.assertEqual(resolved.path.stat().st_mode & 0o777, 0o400)
        self.assertEqual(resolved.path.parent.stat().st_mode & 0o777, 0o700)
        with self.database.transaction(immediate=False) as session:
            row = session.get(SecretReference, "license-reference")
            self.assertEqual(row.reference, str(self.source))
            self.assertNotIn("opaque-private-license-value", repr(row.__dict__))

    def test_cross_project_disabled_and_changed_reference_fail_closed(self):
        for field, value in (("project_id", "project-b"), ("enabled", False), ("reference", "/other/path")):
            with self.database.transaction() as session:
                row = session.get(SecretReference, "license-reference")
                original = getattr(row, field)
                setattr(row, field, value)
            with self.subTest(field=field), self.assertRaises(SecretError) as error:
                self.resolver.resolve(self.job, self.attempt, self.owner)
            self.assertNotIn("opaque-private-license-value", str(error.exception))
            with self.database.transaction() as session:
                setattr(session.get(SecretReference, "license-reference"), field, original)
        self.bind_spec(self.make_spec(project_id="project-b"))
        with self.assertRaises(SecretError):
            self.resolver.resolve(self.job, self.attempt, self.owner)

    def test_option_overrides_and_foreign_option_bindings_refused(self):
        self.bind_spec(self.make_spec(options={"license_key": "literal-override"}))
        with self.assertRaises(SecretError):
            self.resolver.validate_spec(self.spec)
        self.bind_spec(self.make_spec(secret_refs={"wrong_option": "license-reference"}))
        with self.assertRaises(SecretError):
            self.resolver.validate_spec(self.spec)

    def test_component_role_and_identity_limit_delivery(self):
        self.bind_spec(self.make_spec(participant=True, build=True))
        owner = self.resolver.resolve(self.job, self.attempt, self.spec.components[0])
        self.assertIsNotNone(owner.path)
        for component in self.spec.components[1:]:
            result = self.resolver.resolve(self.job, self.attempt, component)
            self.assertIsNone(result.path)
            self.assertEqual(result.redaction_values, ())
        fake = SimpleNamespace(component_id="owner", role="participant", participant_id=None)
        with self.assertRaises(SecretError):
            self.resolver.resolve(self.job, self.attempt, fake)

    def test_explicit_component_scope_cannot_expand_by_role(self):
        self.catalog["license-reference"]["component_ids"] = ["different-owner"]
        resolver = SecretResolver(self.database, self.root / "scoped", self.catalog)
        with self.assertRaises(SecretError):
            resolver.validate_spec(self.spec)

    def test_source_build_and_broad_credentials_cannot_be_approved(self):
        for role in ("build", "source", "platform", "init"):
            with self.subTest(role=role), self.assertRaises(SecretError):
                ApprovedSecretReference("ref", "project-a", self.source, frozenset({role}), frozenset({"license_key"}))
        for option in ("aws_access_key", "git_token", "docker-password", "manager_signing_key",
                       "database_password", "oidc_client_secret", "runtime_socket", "dataset_npz", "target_round"):
            with self.subTest(option=option), self.assertRaises(SecretError):
                ApprovedSecretReference("ref", "project-a", self.source, frozenset({"owner"}), frozenset({option}))
        with self.assertRaises(SecretError):
            ApprovedSecretReference("ref", "project-a", self.source, frozenset({"owner"}),
                                    frozenset({"license_key"}), purpose="human_access_token")

    def test_no_network_paths_unscoped_paths_or_inline_material(self):
        for source in ("https://secret-provider.invalid/key", "file:///root/key", "../key"):
            invalid = dict(self.catalog["license-reference"], path=source)
            with self.subTest(source=source), self.assertRaises(SecretError):
                SecretResolver(self.database, self.root / "other", {"license-reference": invalid})
        for value in (str(self.source), "opaque-private-license-value", {"path": str(self.source)}):
            with self.subTest(value=value), self.assertRaises(SecretError):
                SecretResolver(self.database, self.root / "other", {"license-reference": value})

    def test_private_regular_source_file_required(self):
        self.source.chmod(0o644)
        with self.assertRaises(SecretError):
            self.resolver.resolve(self.job, self.attempt, self.owner)
        self.source.chmod(0o600)
        backup = self.material / "backup"
        self.source.rename(backup)
        self.source.symlink_to(backup)
        with self.assertRaises(SecretError):
            self.resolver.resolve(self.job, self.attempt, self.owner)
        self.source.unlink()
        backup.rename(self.source)
        os.link(self.source, backup)
        with self.assertRaises(SecretError):
            self.resolver.resolve(self.job, self.attempt, self.owner)
        backup.unlink()
        self.material.chmod(0o755)
        with self.assertRaises(SecretError):
            self.resolver.resolve(self.job, self.attempt, self.owner)

    def test_symlink_ancestor_and_output_root_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.material, target_is_directory=True)
        changed = dict(self.catalog["license-reference"], path=str(alias / self.source.name))
        with self.database.transaction() as session:
            session.get(SecretReference, "license-reference").reference = changed["path"]
        resolver = SecretResolver(self.database, self.root / "new", {"license-reference": changed})
        with self.assertRaises(SecretError):
            resolver.resolve(self.job, self.attempt, self.owner)
        with self.database.transaction() as session:
            session.get(SecretReference, "license-reference").reference = str(self.source)
        target = self.root / "other-deliveries"
        target.mkdir(mode=0o700)
        (self.root / "deliveries").symlink_to(target, target_is_directory=True)
        with self.assertRaises(SecretError):
            self.resolver.resolve(self.job, self.attempt, self.owner)

    def test_secret_size_encoding_and_empty_material_bounded(self):
        for value in (b"", b"\0secret", b"\xff", b"x" * 8193):
            self.source.write_bytes(value)
            with self.subTest(value=value[:8]), self.assertRaises(SecretError):
                self.resolver.resolve(self.job, self.attempt, self.owner)

    def test_idempotent_delivery_survives_operator_rotation_until_new_attempt(self):
        first = self.resolver.resolve(self.job, self.attempt, self.owner)
        self.source.write_text("rotated-license")
        self.assertEqual(self.resolver.resolve(self.job, self.attempt, self.owner).redaction_values,
                         first.redaction_values)
        self.job.epoch = 2
        successor = SimpleNamespace(id="attempt-2", job_id="job-a", epoch=2)
        second = self.resolver.resolve(self.job, successor, self.owner)
        self.assertNotEqual(first.path, second.path)
        self.assertEqual(second.redaction_values, ("rotated-license",))
        with self.assertRaises(SecretError):
            self.resolver.resolve(self.job, self.attempt, self.owner)

    def test_existing_manifest_and_current_approval_are_rechecked(self):
        first = self.resolver.resolve(self.job, self.attempt, self.owner)
        with self.database.transaction() as session:
            session.get(SecretReference, "license-reference").enabled = False
        with self.assertRaises(SecretError):
            self.resolver.resolve(self.job, self.attempt, self.owner)
        with self.database.transaction() as session:
            session.get(SecretReference, "license-reference").enabled = True
        value = json.loads(first.path.read_text())
        value["attempt_id"] = "foreign-attempt"
        first.path.chmod(0o600)
        first.path.write_text(json.dumps(value))
        first.path.chmod(0o400)
        with self.assertRaises(SecretError):
            self.resolver.resolve(self.job, self.attempt, self.owner)

    def test_cleanup_requires_confirmed_stop_and_cannot_remove_foreign_manifest(self):
        resolved = self.resolver.resolve(self.job, self.attempt, self.owner)
        with self.assertRaises(SecretError):
            self.resolver.cleanup(resolved)
        self.assertTrue(resolved.path.exists())
        wrong = dict(job_id="job-a", attempt_id="attempt-1", component_id="owner", epoch=2)
        self.assertTrue(self.resolver.cleanup(wrong, termination_confirmed=True))
        self.assertTrue(resolved.path.exists())
        self.assertTrue(self.resolver.cleanup(resolved, termination_confirmed=True))
        self.assertFalse(resolved.path.exists())
        self.assertTrue(self.resolver.cleanup(resolved, termination_confirmed=True))
        self.assertTrue(self.source.exists())

    def test_collection_redacts_resolved_secret_values(self):
        resolved = self.resolver.resolve(self.job, self.attempt, self.owner)
        output = self.root / "state"
        output.mkdir()
        (output / "plugin.log").write_text("license=" + resolved.redaction_values[0])
        (output / "events.jsonl").write_text(json.dumps({"message": resolved.redaction_values[0]}) + "\n")
        with SafeCollector(output, secret_values=resolved.redaction_values) as collector:
            self.assertEqual(collector.logs("plugin.log"), "license=[REDACTED]")
            self.assertEqual(collector.events("events.jsonl"), ({"message": "[REDACTED]"},))
        self.assertNotIn(output, resolved.path.parents)

    def test_total_secret_manifest_size_is_bounded(self):
        references, approvals = {}, {}
        self.source.write_text("x" * 8192)
        with self.database.transaction() as session:
            for index in range(9):
                identifier, option = f"reference-{index}", f"license_key_{index}"
                session.add(SecretReference(id=identifier, project_id="project-a",
                                            reference=str(self.source), enabled=True))
                references[option] = identifier
                approvals[identifier] = dict(self.catalog["license-reference"], option_names=[option])
        self.bind_spec(self.make_spec(secret_refs=references))
        resolver = SecretResolver(self.database, self.root / "bounded", approvals)
        with self.assertRaises(SecretError):
            resolver.resolve(self.job, self.attempt, self.owner)
        self.assertFalse(list((self.root / "bounded").rglob("secrets.json")))

    def test_concurrent_idempotent_delivery_has_one_immutable_snapshot(self):
        start = Barrier(2)

        def deliver(_):
            start.wait(timeout=30)
            return self.resolver.resolve(self.job, self.attempt, self.owner)
        with ThreadPoolExecutor(max_workers=2) as pool:
            values = tuple(pool.map(deliver, range(4)))
        self.assertEqual(len({value.path for value in values}), 1)
        self.assertEqual(len({value.path.stat().st_ino for value in values}), 1)
        self.assertTrue(all(value.redaction_values == values[0].redaction_values for value in values))
        self.assertFalse(list((self.root / "deliveries").rglob(".secret-tmp-*")))

    def test_manifest_certificate_free_binding_is_exact_and_strict(self):
        resolved = self.resolver.resolve(self.job, self.attempt, self.owner)
        for update in ({"job_id": "other"}, {"component_id": "other"}, {"epoch": True},
                       {"schema_version": True}, {"role": "build"}, {"references": {}}):
            original = json.loads(resolved.path.read_text())
            changed = dict(original, **update)
            resolved.path.chmod(0o600)
            resolved.path.write_text(json.dumps(changed))
            resolved.path.chmod(0o400)
            with self.subTest(update=update), self.assertRaises(SecretError):
                read_secret_manifest(resolved.path, resolved)
            resolved.path.chmod(0o600)
            resolved.path.write_text(json.dumps(original))
            resolved.path.chmod(0o400)


if __name__ == "__main__":
    unittest.main()
