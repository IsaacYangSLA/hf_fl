"""Generic cache integrity, offline worker staging, and frozen source tests."""
from __future__ import annotations

from contextlib import redirect_stderr
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from deploy.jobs.runtime import build_image


class OfflineBuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "source"
        self.repo.mkdir()
        (self.repo / "deploy/jobs/runtime").mkdir(parents=True)
        (self.repo / "deploy/jobs/runtime/Dockerfile").write_text("FROM approved")
        self.release = self.root / "release"
        self.release.mkdir()
        self.frontend = self.release / "build-wheelhouse"
        self.projects = self.release / "wheels"
        self.dependencies = self.root / "worker-cache"
        for path in (self.frontend, self.projects, self.dependencies):
            path.mkdir()
        self.frontend_records = [self.wheel(self.frontend, name, version)
                                 for name, version in build_image.BUILD_FRONTEND.items()]
        self.write_frontend()
        sources = {"hf2l/client_steps.py": b"client",
                   "hf2l_jobs/runtime.py": b"runtime",
                   "hf2l_jobs/workflow.py": b"workflow",
                   "hf2l_jobs/build.py": b"build"}
        for member, content in sources.items():
            source = self.repo / (member if member.startswith("hf2l/") else "packages/jobs/src/" + member)
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(content)
        self.project_records = [
            self.wheel(self.projects, name, "2.0",
                       {member: content for member, content in sources.items()
                        if member.startswith("hf2l/" if name == "hf2l" else "hf2l_jobs/")}
                       if name != "hf2l-exchange" else {})
            for name in sorted(build_image.PROJECT_NAMES)]
        (self.projects / "manifest.json").write_text(json.dumps({"wheels": self.project_records}))
        self.dependency_records = [
            self.wheel(self.dependencies, name, "1.0")
            for name in sorted(build_image.PROJECT_NAMES)]
        self.dependency_records += [
            self.wheel(self.dependencies, name, version)
            for name, version in build_image.BUILD_INPUTS.items()]
        self.dependency_records.append(self.wheel(self.dependencies, "torch", "2.14.1+cpu"))
        self.dependency_records += [self.wheel(self.dependencies, "dependency-" + str(i), "1.0")
                                    for i in range(39)]
        self.write_dependencies()
        self.calls = []

    def tearDown(self):
        self.temporary.cleanup()

    def wheel(self, directory, name, version, files=None):
        path = directory / (name.replace("-", "_") + "-" + version + "-py3-none-any.whl")
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(name.replace("-", "_") + "-" + version + ".dist-info/METADATA",
                             "Metadata-Version: 2.1\nName: " + name + "\nVersion: " + version + "\n")
            for member, content in (files or {}).items():
                archive.writestr(member, content)
        return {"filename": path.name, "name": name, "version": version,
                "sha256": build_image.digest(path), "size_bytes": path.stat().st_size}

    def write_frontend(self):
        (self.release / "build-wheel-manifest.json").write_text(json.dumps(self.frontend_records))

    def write_dependencies(self):
        (self.dependencies / "wheel-manifest.json").write_text(json.dumps(self.dependency_records))

    def argv(self):
        return ["--output-dir", str(self.root / "output"), "--stage-only",
                "--base-image", "sha256:" + "c" * 64,
                "--reuse-wheelhouse", str(self.dependencies),
                "--project-wheelhouse", str(self.projects),
                "--build-wheelhouse", str(self.frontend)]

    def reject_before_subprocess(self):
        with patch.object(build_image.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                build_image.main([*self.argv(), "--source-commit", "a" * 40])
            run.assert_not_called()
        self.assertFalse((self.root / "output").exists())

    def test_missing_approved_frontend_rejected_before_even_git(self):
        shutil.rmtree(self.frontend)
        self.reject_before_subprocess()

    def test_tampered_approved_frontend_rejected_before_subprocess(self):
        (self.frontend / self.frontend_records[0]["filename"]).write_bytes(b"tampered")
        self.reject_before_subprocess()

    def test_missing_declared_cache_arguments_fail_closed(self):
        for flag in ("--build-wheelhouse", "--project-wheelhouse"):
            argv = self.argv()
            index = argv.index(flag)
            del argv[index:index + 2]
            with patch.object(build_image.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    build_image.main(argv)
                run.assert_not_called()

    def test_missing_frontend_record_rejected(self):
        self.frontend_records.pop()
        self.write_frontend()
        self.reject_before_subprocess()

    def test_wrong_pinned_frontend_version_rejected(self):
        old = self.frontend_records.pop()
        (self.frontend / old["filename"]).unlink()
        self.frontend_records.append(self.wheel(self.frontend, old["name"], "0.0"))
        self.write_frontend()
        self.reject_before_subprocess()

    def test_unmanifested_frontend_wheel_rejected(self):
        self.wheel(self.frontend, "unapproved", "1.0")
        self.reject_before_subprocess()

    def test_duplicate_distribution_rejected(self):
        self.frontend_records.append(dict(self.frontend_records[0]))
        self.write_frontend()
        self.reject_before_subprocess()

    def test_traversal_record_rejected(self):
        self.frontend_records[0]["filename"] = "../outside.whl"
        self.write_frontend()
        self.reject_before_subprocess()

    def test_frontend_symlink_rejected(self):
        path = self.frontend / self.frontend_records[0]["filename"]
        target = self.root / "linked.whl"
        path.rename(target)
        path.symlink_to(target)
        self.reject_before_subprocess()

    def test_manifest_symlink_rejected(self):
        path = self.release / "build-wheel-manifest.json"
        target = self.root / "linked.json"
        path.rename(target)
        path.symlink_to(target)
        self.reject_before_subprocess()

    def test_metadata_identity_mismatch_rejected(self):
        self.frontend_records[0]["name"] = "foreign"
        self.write_frontend()
        self.reject_before_subprocess()

    def test_filename_metadata_identity_mismatch_rejected(self):
        record = self.frontend_records[0]
        path = self.frontend / record["filename"]
        record["filename"] = "foreign-" + record["version"] + "-py3-none-any.whl"
        path.rename(self.frontend / record["filename"])
        self.write_frontend()
        self.reject_before_subprocess()

    def test_frontend_directory_symlink_rejected(self):
        target = self.release / "real-frontends"
        self.frontend.rename(target)
        self.frontend.symlink_to(target, target_is_directory=True)
        self.reject_before_subprocess()

    def test_missing_manifested_wheel_rejected(self):
        (self.frontend / self.frontend_records[0]["filename"]).unlink()
        self.reject_before_subprocess()

    def test_all_cached_wheels_verified_including_discarded_old_project(self):
        self.assertEqual(len(self.dependency_records), 46)
        path = self.dependencies / self.dependency_records[0]["filename"]
        path.write_bytes(b"tampered old project")
        self.reject_before_subprocess()

    def test_missing_torch_cannot_trigger_online_fallback(self):
        record = next(item for item in self.dependency_records if item["name"] == "torch")
        self.dependency_records.remove(record)
        (self.dependencies / record["filename"]).unlink()
        self.write_dependencies()
        self.reject_before_subprocess()

    def test_missing_worker_frontend_cannot_trigger_online_fallback(self):
        record = next(item for item in self.dependency_records if item["name"] == "build")
        self.dependency_records.remove(record)
        (self.dependencies / record["filename"]).unlink()
        self.write_dependencies()
        self.reject_before_subprocess()

    def fake_run(self, command, **kwargs):
        command = list(map(str, command))
        self.calls.append((command, kwargs.get("env")))
        if "venv" in command:
            (Path(command[-1]) / "bin").mkdir(parents=True)
        elif "download" in command:
            for path in self.projects.glob("*.whl"):
                shutil.copy2(path, Path(command[command.index("--dest") + 1]) / path.name)
        elif "assert sys.version_info" in " ".join(command):
            kwargs["stdout"].write("3.14 test interpreter")
        return subprocess.CompletedProcess(command, 0)

    def test_cached_stage_uses_only_declared_offline_commands_and_records_all_hashes(self):
        # The helper's Dockerfile comes from its own trusted source location.
        with patch.object(build_image, "ROOT", self.repo), \
             patch.object(build_image.subprocess, "run", side_effect=self.fake_run):
            self.assertEqual(build_image.main(self.argv()), 0)
        commands = [command for command, _ in self.calls]
        venv, install = commands[0], commands[2]
        self.assertEqual(venv[1:5], ["--no-config", "venv", "--offline", "--no-python-downloads"])
        self.assertNotIn("--seed", venv)
        for flag in ("--offline", "--no-config", "--no-index", "--no-deps", "--no-python-downloads"):
            self.assertIn(flag, install)
        wheel_args = [item for item in install if item.endswith(".whl")]
        self.assertEqual(set(wheel_args), {str(self.frontend / item["filename"])
                                          for item in self.frontend_records})
        self.assertEqual(len(wheel_args), 7)
        for command in commands:
            self.assertNotIn("--index-url", command)
            self.assertNotIn("--extra-index-url", command)
            self.assertNotIn("--seed", command)
            self.assertFalse(any(item.startswith("https://") for item in command))
            if "download" in command:
                self.assertIn("--no-index", command)
        for _, env in self.calls:
            self.assertEqual(env["PIP_NO_INDEX"], "1")
            self.assertEqual(env["UV_OFFLINE"], "true")
        output = self.root / "output"
        stage = Path((output / "latest-build.txt").read_text().strip())
        manifest = json.loads((stage / "manifest.json").read_text())
        self.assertEqual(manifest["host_build_frontend"], self.frontend_records)
        self.assertEqual(manifest["reused_wheels"], self.dependency_records)
        self.assertEqual(len(manifest["wheels"]), 46)
        versions = {item["name"]: item["version"] for item in manifest["wheels"]}
        for name in build_image.PROJECT_NAMES:
            self.assertEqual(versions[name], "2.0")


    def write_projects(self, records):
        (self.projects / "manifest.json").write_text(json.dumps({"wheels": records}))

    def copy_projects(self):
        output = self.root / "copied-projects"
        output.mkdir()
        build_image.reuse_project_wheels(self.projects, output)
        self.assertEqual({path.name for path in output.iterdir()},
                         {record["filename"] for record in self.project_records})
        return output

    def test_base_image_is_required_before_any_action(self):
        argv = self.argv()
        index = argv.index("--base-image")
        del argv[index:index + 2]
        with patch.object(build_image.subprocess, "run") as run, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                build_image.main(argv)
            self.assertEqual(error.exception.code, 2)
            run.assert_not_called()
        self.assertFalse((self.root / "output").exists())

    def test_tracked_untracked_and_ignored_source_changes_are_rejected(self):
        expected = "a" * 40
        for status in (" M source.py", "?? untracked.py", "!! ignored.py"):
            with self.subTest(status=status):
                replies = [subprocess.CompletedProcess([], 0, stdout=expected),
                           subprocess.CompletedProcess([], 0, stdout=status)]
                with patch.object(build_image.subprocess, "run", side_effect=replies) as run:
                    with self.assertRaisesRegex(ValueError, "frozen release commit"):
                        build_image.main([*self.argv(), "--source-commit", expected])
                    self.assertEqual(run.call_count, 2)
                    command = run.call_args_list[1].args[0]
                    self.assertIn("--untracked-files=all", command)
                    self.assertIn("--ignored", command)
                self.assertFalse((self.root / "output").exists())

    def test_named_project_records_remain_compatible(self):
        self.copy_projects()

    def test_legacy_project_records_remain_compatible(self):
        self.write_projects([{"filename": item["filename"], "sha256": item["sha256"]}
                             for item in self.project_records])
        self.copy_projects()

    def test_legacy_project_records_are_accepted_by_cached_cli_preflight(self):
        self.write_projects([{"filename": item["filename"], "sha256": item["sha256"]}
                             for item in self.project_records])
        args = build_image.parser().parse_args(self.argv())
        with patch.object(build_image.subprocess, "run") as run:
            build_image.validate_offline_inputs(args)
            run.assert_not_called()

    def test_partial_project_identity_fields_are_rejected(self):
        for omitted in ("name", "version"):
            with self.subTest(omitted=omitted):
                records = [dict(item) for item in self.project_records]
                del records[0][omitted]
                self.write_projects(records)
                self.reject_before_subprocess()

    def test_explicit_empty_project_identity_is_not_legacy(self):
        records = [dict(item) for item in self.project_records]
        records[0].update(name=None, version=None)
        self.write_projects(records)
        self.reject_before_subprocess()



    def test_duplicate_frontend_json_identity_fields_are_rejected(self):
        path = self.release / "build-wheel-manifest.json"
        field = '"name": "' + self.frontend_records[0]["name"] + '"'
        path.write_text(path.read_text().replace(field, field + ", " + field, 1))
        self.reject_before_subprocess()

    def test_duplicate_legacy_project_json_hash_fields_are_rejected(self):
        records = [{"filename": item["filename"], "sha256": item["sha256"]}
                   for item in self.project_records]
        self.write_projects(records)
        path = self.projects / "manifest.json"
        field = '"sha256": "' + records[0]["sha256"] + '"'
        path.write_text(path.read_text().replace(field, field + ", " + field, 1))
        self.reject_before_subprocess()

    def test_ambiguous_project_metadata_identity_is_rejected(self):
        record = self.project_records[0]
        path = self.projects / record["filename"]
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(record["name"].replace("-", "_") + "-2.0.dist-info/METADATA",
                             "Metadata-Version: 2.1\nName: " + record["name"]
                             + "\nName: " + record["name"] + "\nVersion: 2.0\n")
        record["sha256"] = build_image.digest(path)
        record["size_bytes"] = path.stat().st_size
        self.write_projects(self.project_records)
        self.reject_before_subprocess()

    def test_explicit_project_identity_is_verified(self):
        for field, value in (("name", "foreign"), ("version", "0.0")):
            with self.subTest(field=field):
                records = [dict(item) for item in self.project_records]
                records[0][field] = value
                self.write_projects(records)
                self.reject_before_subprocess()

    def test_duplicate_project_manifest_records_are_rejected(self):
        self.write_projects([*self.project_records, dict(self.project_records[0])])
        self.reject_before_subprocess()

    def test_legacy_project_filename_identity_is_verified(self):
        records = [{"filename": item["filename"], "sha256": item["sha256"]}
                   for item in self.project_records]
        path = self.projects / records[0]["filename"]
        records[0]["filename"] = "foreign-2.0-py3-none-any.whl"
        path.rename(self.projects / records[0]["filename"])
        self.write_projects(records)
        self.reject_before_subprocess()

    def test_legacy_project_hash_is_verified_before_metadata_is_derived(self):
        self.write_projects([{"filename": item["filename"], "sha256": item["sha256"]}
                             for item in self.project_records])
        (self.projects / self.project_records[0]["filename"]).write_bytes(b"not approved wheel bytes")
        self.reject_before_subprocess()

    def test_project_wheel_symlink_is_rejected(self):
        path = self.projects / self.project_records[0]["filename"]
        target = self.root / "linked-project.whl"
        path.rename(target)
        path.symlink_to(target)
        self.reject_before_subprocess()

    def test_frontend_does_not_accept_legacy_identity_omissions(self):
        self.frontend_records = [{"filename": item["filename"], "sha256": item["sha256"]}
                                 for item in self.frontend_records]
        self.write_frontend()
        self.reject_before_subprocess()

    def test_dependencies_do_not_accept_legacy_identity_omissions(self):
        self.dependency_records = [{"filename": item["filename"], "sha256": item["sha256"]}
                                   for item in self.dependency_records]
        self.write_dependencies()
        self.reject_before_subprocess()



    def test_cached_commands_strip_inherited_pip_and_uv_discovery_settings(self):
        hostile = {
            "PIP_FIND_LINKS": "https://example.invalid/wheels",
            "PIP_INDEX_URL": "https://example.invalid/simple",
            "PIP_EXTRA_INDEX_URL": "https://example.invalid/extra",
            "PIP_REQUIREMENT": "/untrusted/requirements.txt",
            "PIP_CONSTRAINT": "/untrusted/constraints.txt",
            "PIP_TRUSTED_HOST": "example.invalid",
            "PIP_TARGET": "/untrusted/install",
            "PIP_CONFIG_FILE": "/untrusted/pip.conf",
            "UV_FIND_LINKS": "https://example.invalid/wheels",
            "UV_INDEX_URL": "https://example.invalid/simple",
            "UV_EXTRA_INDEX_URL": "https://example.invalid/extra",
            "UV_CONSTRAINT": "/untrusted/constraints.txt",
            "UV_BUILD_CONSTRAINT": "/untrusted/build-constraints.txt",
            "UV_OVERRIDE": "/untrusted/overrides.txt",
            "UV_CONFIG_FILE": "/untrusted/uv.toml",
            "UV_PROJECT_ENVIRONMENT": "/untrusted/environment",
            "UV_ENV_FILE": "/untrusted/env",
        }
        with patch.dict(os.environ, hostile), \
             patch.object(build_image, "ROOT", self.repo), \
             patch.object(build_image.subprocess, "run", side_effect=self.fake_run):
            self.assertEqual(build_image.main(self.argv()), 0)
        safe = {"PIP_CONFIG_FILE": os.devnull, "PIP_NO_INDEX": "1",
                "PIP_DISABLE_PIP_VERSION_CHECK": "1", "UV_OFFLINE": "true", "UV_NO_CONFIG": "true", "UV_PYTHON_DOWNLOADS": "never"}
        checked = 0
        for command, environment in self.calls:
            if "pip" not in command and "venv" not in command:
                continue
            checked += 1
            for key in hostile:
                if key not in safe:
                    self.assertNotIn(key, environment, msg=key)
            for key, value in safe.items():
                self.assertEqual(environment.get(key), value, msg=key)
        self.assertEqual(checked, 3)

    def approve_direct_url_requirement(self, directory, record, requirement):
        path = directory / record["filename"]
        with zipfile.ZipFile(path) as archive:
            entries = {member: archive.read(member) for member in archive.namelist()}
        metadata = next(member for member in entries if member.endswith(".dist-info/METADATA"))
        entries[metadata] += ("Requires-Dist: " + requirement + "\n").encode()
        with zipfile.ZipFile(path, "w") as archive:
            for member, content in entries.items():
                archive.writestr(member, content)
        record["sha256"] = build_image.digest(path)
        record["size_bytes"] = path.stat().st_size

    def reject_approved_direct_reference_variants(self, directory, record, write_manifest):
        path = directory / record["filename"]
        original_bytes, original_record = path.read_bytes(), dict(record)
        for requirement in (
            "remote-package @ https://example.invalid/remote_package-1.0-py3-none-any.whl",
            "remote-package[extra]@https://example.invalid/remote_package-1.0-py3-none-any.whl",
            "remote-package@file:///untrusted/remote_package-1.0-py3-none-any.whl",
        ):
            with self.subTest(requirement=requirement):
                path.write_bytes(original_bytes)
                record.clear()
                record.update(original_record)
                self.approve_direct_url_requirement(directory, record, requirement)
                write_manifest()
                self.reject_before_subprocess()

    def test_approved_project_direct_url_dependency_rejected_before_subprocess(self):
        self.reject_approved_direct_reference_variants(
            self.projects, self.project_records[0],
            lambda: self.write_projects(self.project_records))

    def test_approved_cached_dependency_direct_url_rejected_before_subprocess(self):
        record = next(item for item in self.dependency_records if item["name"] == "dependency-0")
        self.reject_approved_direct_reference_variants(
            self.dependencies, record, self.write_dependencies)


if __name__ == "__main__":
    unittest.main()
