"""Offline builds execute real hooks only through sandbox worker invocation."""
from __future__ import annotations

import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hf2l_jobs.build import BuildConfig, BuildSafetyError, _environment, run_worker
from hf2l_jobs.domain import JobSpec


class OfflineBuildTests(unittest.TestCase):
    def setUp(self):
        try:
            metadata.version("build")
            metadata.version("setuptools")
        except metadata.PackageNotFoundError:
            if os.environ.get("JOBS_REQUIRE_RUNTIME_TESTS") == "1":
                raise
            self.skipTest("Offline build tests require approved build frontend/backend tools")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.state = self.root / "state"

    def config(self, source=None, state=None, dependencies=None):
        source, state = source or self.source, state or self.state
        spec = JobSpec.model_validate({
            "project_id": "test", "name": "Offline build", "source_id": "approved",
            "source_commit": "a" * 40, "runtime_image": "approved-runtime",
            "plugin": "lenet", "components": [
                {"component_id": "owner", "role": "owner", "resources": {
                    "pool_id": "cpu", "cpu_millicores": 500, "memory_bytes": 1 << 28, "disk_bytes": 1 << 28}},
                {"component_id": "build", "role": "build", "resources": {
                    "pool_id": "cpu", "cpu_millicores": 500, "memory_bytes": 1 << 28, "disk_bytes": 1 << 28}}],
            "target_round": 1, "max_duration_seconds": 60})
        manifest = {p.relative_to(source).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in source.rglob("*") if p.is_file()}
        return BuildConfig(job_id="job-a", attempt_id="attempt-a", component_id="build", epoch=1,
                           spec=spec, spec_digest=spec.digest, source_dir=str(source), state_dir=str(state),
                           source_manifest=manifest, approved_dependencies=dependencies or {
                               "build": metadata.version("build"), "setuptools": metadata.version("setuptools")})

    def setuptools_source(self, requirements='["setuptools>=61"]'):
        (self.source / "pyproject.toml").write_text(
            '[build-system]\nrequires = ' + requirements +
            '\nbuild-backend = "setuptools.build_meta"\n'
            '[project]\nname = "hf2l-private-test"\nversion = "0.1.0"\n'
            '[tool.setuptools]\npy-modules = ["private_test"]\n')
        (self.source / "private_test.py").write_text('VALUE = "private job source"\n')

    def test_actual_offline_wheel_and_idempotent_attempt_rotation(self):
        self.setuptools_source()
        config = self.config()
        self.state.mkdir()
        for reserved in ("cache", "logs", "artifacts"):
            (self.state / reserved).mkdir()
        before = {p.name: p.read_bytes() for p in self.source.iterdir()}
        self.assertEqual(run_worker(config), 0)
        result = json.loads((self.state / "artifacts/build.json").read_text())
        self.assertEqual(result["status"], "completed")
        wheel = self.state / "artifacts" / result["wheel"]["filename"]
        self.assertEqual(hashlib.sha256(wheel.read_bytes()).hexdigest(), result["wheel"]["sha256"])
        self.assertEqual({p.name: p.read_bytes() for p in self.source.iterdir()}, before)
        rotated = config.model_copy(update={"attempt_id": "attempt-b", "epoch": 2})
        self.assertEqual(run_worker(rotated), 0)
        self.assertEqual(json.loads((self.state / "artifacts/build.json").read_text()), result)
        wheel.chmod(0o600)
        wheel.write_bytes(wheel.read_bytes() + b"changed")
        with self.assertRaises(BuildSafetyError):
            run_worker(rotated)

    def test_fixed_runtime_entrypoint_dispatches_build_without_exchange(self):
        self.setuptools_source()
        configuration = self.root / "runtime.json"
        configuration.write_text(json.dumps(self.config().to_dict()))
        result = subprocess.run(
            [sys.executable, "-m", "hf2l_jobs.runtime", "--config", str(configuration)],
            check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(json.loads((self.state / "artifacts/build.json").read_text())["status"], "completed")

    def test_source_hook_receives_no_provider_credentials_and_cannot_import_in_manager(self):
        hook = '''
import os
import pathlib
import zipfile
def get_requires_for_build_wheel(config_settings=None):
    assert os.environ.get("HF_TOKEN") is None
    assert os.environ.get("AWS_SECRET_ACCESS_KEY") is None
    assert os.environ.get("GIT_ASKPASS") is None
    assert os.environ.get("HTTPS_PROXY") is None
    assert os.environ["PIP_NO_INDEX"] == "1"
    return []
def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    name = "private_hook-0.1-py3-none-any.whl"
    with zipfile.ZipFile(pathlib.Path(wheel_directory) / name, "w") as z:
        z.writestr("private_hook.py", "PRIVATE = True")
    return name
'''
        (self.source / "pyproject.toml").write_text(
            '[build-system]\nrequires = []\nbuild-backend = "offline_hook"\nbackend-path = ["."]\n')
        (self.source / "offline_hook.py").write_text(hook)
        config = self.config(dependencies={"build": metadata.version("build")})
        self.assertNotIn("offline_hook", sys.modules)
        with patch.dict(os.environ, {"HF_TOKEN": "synthetic", "AWS_SECRET_ACCESS_KEY": "synthetic",
                                     "GIT_ASKPASS": "synthetic", "HTTPS_PROXY": "https://synthetic.invalid"}):
            self.assertEqual(run_worker(config), 0)
        self.assertNotIn("offline_hook", sys.modules)

    def test_url_unapproved_and_changed_dependency_inputs_are_rejected(self):
        self.setuptools_source('["setuptools @ https://example.invalid/setuptools.whl"]')
        with self.assertRaises(BuildSafetyError):
            run_worker(self.config())
        other = self.root / "other"
        other.mkdir()
        self.source = other
        self.setuptools_source('["package-not-approved>=1"]')
        with self.assertRaises(BuildSafetyError):
            run_worker(self.config(state=self.root / "state-other"))
        with self.assertRaises(BuildSafetyError):
            run_worker(self.config(state=self.root / "state-wrong", dependencies={
                "build": "0.0.0", "setuptools": metadata.version("setuptools")}))

    def test_extra_fields_command_credentials_network_and_foreign_binding_are_rejected(self):
        self.setuptools_source()
        config = self.config()
        for key, value in (("command", ["sh"]), ("credentials", "synthetic"),
                           ("proxy_socket", "/socket"), ("network", "host")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                BuildConfig.model_validate({**config.to_dict(), key: value})
        for key, value in (("component_id", "owner"), ("spec_digest", "0" * 64),
                           ("project_subdir", "../other"), ("approved_dependencies", {"build": "https://secret.invalid"})):
            with self.subTest(key=key), self.assertRaises(ValueError):
                BuildConfig.model_validate({**config.to_dict(), key: value})

    def test_full_manifest_rejects_extra_source_and_symlinks_before_hooks(self):
        self.setuptools_source()
        config = self.config()
        (self.source / "unlisted.py").write_text("raise AssertionError('must not import')")
        with self.assertRaises(BuildSafetyError):
            run_worker(config)
        (self.source / "unlisted.py").unlink()
        (self.source / "foreign").symlink_to(self.root)
        with self.assertRaises(BuildSafetyError):
            run_worker(config)

    def test_failed_backend_and_dynamic_dependency_preserve_failure_progress(self):
        (self.source / "pyproject.toml").write_text(
            '[build-system]\nrequires = []\nbuild-backend = "unapproved_hook"\nbackend-path = ["."]\n')
        (self.source / "unapproved_hook.py").write_text(
            'def get_requires_for_build_wheel(config_settings=None):\n'
            '    return ["private-retrieval @ https://example.invalid/a.whl"]\n'
            'def build_wheel(*args, **kwargs):\n'
            '    raise AssertionError("must reject before wheel hook")\n')
        with self.assertRaises(BuildSafetyError):
            run_worker(self.config(dependencies={"build": metadata.version("build")}))
        self.assertEqual(json.loads((self.state / "progress.json").read_text())["phase"], "failed")
        self.assertFalse((self.state / "artifacts/build.json").exists())

    def test_private_state_cannot_be_adopted_without_immutable_binding(self):
        self.setuptools_source()
        self.state.mkdir()
        (self.state / "foreign.txt").write_text("another job")
        with self.assertRaises(BuildSafetyError):
            run_worker(self.config())

    def test_sanitized_environment_uses_only_job_private_paths(self):
        self.state.mkdir()
        with patch.dict(os.environ, {"PIP_INDEX_URL": "https://synthetic.invalid", "LD_PRELOAD": "bad"}):
            value = _environment(self.state)
        self.assertNotIn("PIP_INDEX_URL", value)
        self.assertNotIn("LD_PRELOAD", value)
        for name in ("HOME", "TMPDIR", "XDG_CACHE_HOME"):
            self.assertTrue(Path(value[name]).is_relative_to(self.state))

    def test_importing_build_contract_never_loads_backend(self):
        command = [sys.executable, "-c",
                   "import sys; import hf2l_jobs.build; "
                   "assert 'build' not in sys.modules; assert 'setuptools' not in sys.modules; "
                   "assert 'torch' not in sys.modules; assert 'hf2l' not in sys.modules"]
        subprocess.run(command, check=True, capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
