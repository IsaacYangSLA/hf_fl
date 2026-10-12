"""Private built wheels are verified and installed only by the sandbox runtime."""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from hf2l_jobs.domain import JobSpec
from hf2l_jobs.runtime import RuntimeSafetyError, _install_built_artifacts, _load_plugin
from hf2l_jobs.workflow import RuntimeConfig

try:
    from hf2l.common.fs import read_json
except ImportError as exc:
    if os.environ.get("JOBS_REQUIRE_RUNTIME_TESTS") == "1":
        raise
    raise unittest.SkipTest("Sandbox wheel integration requires HF2L runtime extras") from exc


class PrivateWheelInstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.build = self.root / "build"
        self.build.mkdir()
        self.state = self.root / "state"
        self.module = "private_generated_runtime"
        self.filename = "private_generated_runtime-0.1-py3-none-any.whl"
        self.wheel = self.build / self.filename
        prefix = "private_generated_runtime-0.1.dist-info/"
        contents = {
            self.module + ".py": b"VALUE = 41\n",
            prefix + "WHEEL": b"Wheel-Version: 1.0\nGenerator: hf2l-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
            prefix + "METADATA": b"Metadata-Version: 2.1\nName: private-generated-runtime\nVersion: 0.1\n",
        }
        records = []
        for name, data in contents.items():
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            records.append(name + ",sha256=" + digest + "," + str(len(data)))
        records.append(prefix + "RECORD,,")
        contents[prefix + "RECORD"] = ("\n".join(records) + "\n").encode()
        with zipfile.ZipFile(self.wheel, "w") as archive:
            for name, data in contents.items():
                archive.writestr(name, data)
        self.artifact = {"sha256": hashlib.sha256(self.wheel.read_bytes()).hexdigest(),
                         "size_bytes": self.wheel.stat().st_size}
        self.bytecode = sys.dont_write_bytecode
        self.bytecode_environment = os.environ.get("PYTHONDONTWRITEBYTECODE")
        self.path = list(sys.path)
        self.addCleanup(self.restore_imports)

    def restore_imports(self):
        sys.dont_write_bytecode = self.bytecode
        if self.bytecode_environment is None:
            os.environ.pop("PYTHONDONTWRITEBYTECODE", None)
        else:
            os.environ["PYTHONDONTWRITEBYTECODE"] = self.bytecode_environment
        sys.path[:] = self.path
        sys.modules.pop(self.module, None)

    def config(self, epoch=1):
        spec = JobSpec.model_validate({
            "project_id": "test", "name": "Private wheel", "source_id": "approved",
            "source_commit": "a" * 40, "runtime_image": "approved-cpu",
            "plugin": self.module, "components": [{
                "component_id": "owner", "role": "owner", "resources": {
                    "pool_id": "cpu", "cpu_millicores": 500,
                    "memory_bytes": 1 << 28, "disk_bytes": 1 << 28}}],
            "target_round": 1, "max_duration_seconds": 60})
        config = RuntimeConfig.model_validate({
            "role": "owner", "job_id": "job-a", "attempt_id": "attempt-" + str(epoch),
            "component_id": "owner", "space_id": "space-a", "epoch": epoch,
            "spec": spec.to_dict(), "spec_digest": spec.digest,
            "source_dir": str(self.source), "state_dir": str(self.state),
            "built_artifacts": {self.filename: self.artifact}})
        # Mirrors the fixed /job/build mount in a host test; production cannot
        # provide another build_dir because the actual config rejects it.
        return config.model_copy(update={"build_dir": str(self.build)})

    def test_real_offline_install_import_and_attempt_restart_preserve_bytes(self):
        plugin = _load_plugin(self.config())
        self.assertEqual(plugin.VALUE, 41)
        self.assertTrue(Path(plugin.__file__).is_relative_to(self.state / "site-packages"))
        marker = read_json(self.state / "private-build-install.json")
        self.assertEqual(marker["phase"], "installed")
        self.assertFalse(any(self.state.rglob("*.pyc")))
        with patch("subprocess.run", side_effect=AssertionError("must reuse verified installation")):
            self.assertEqual(_load_plugin(self.config(epoch=2)).VALUE, 41)
        self.assertEqual(read_json(self.state / "private-build-install.json"), marker)

    def test_installed_module_tampering_is_rejected_before_import_or_reinstall(self):
        _load_plugin(self.config())
        (self.state / "site-packages" / (self.module + ".py")).write_text("VALUE = 99\n")
        with patch("subprocess.run", side_effect=AssertionError("must not overwrite tampered state")):
            with self.assertRaises(RuntimeSafetyError):
                _load_plugin(self.config(epoch=2))

    def test_extra_wheel_directory_and_metadata_symlink_are_rejected(self):
        config = self.config()
        foreign = self.build / "foreign.whl"
        foreign.write_bytes(b"foreign")
        with self.assertRaises(RuntimeSafetyError):
            _install_built_artifacts(config)
        foreign.unlink()
        extra = self.build / "foreign"
        extra.mkdir()
        with self.assertRaises(RuntimeSafetyError):
            _install_built_artifacts(config)
        extra.rmdir()
        (self.build / "build-result.json").symlink_to(self.wheel)
        with self.assertRaises(RuntimeSafetyError):
            _install_built_artifacts(config)

    def test_wheel_hash_size_and_hardlink_are_rejected(self):
        config = self.config()
        for field, value in (("sha256", "0" * 64), ("size_bytes", self.artifact["size_bytes"] + 1)):
            payload = config.to_dict()
            payload["build_dir"] = "/job/build"
            payload["built_artifacts"][self.filename][field] = value
            changed = RuntimeConfig.model_validate(payload).model_copy(update={"build_dir": str(self.build)})
            # Separate state avoids adopting a changed immutable manifest.
            changed = changed.model_copy(update={"state_dir": str(self.root / field)})
            with self.subTest(field=field), self.assertRaises(RuntimeSafetyError):
                _install_built_artifacts(changed)
        hardlink = self.root / "hardlink.whl"
        hardlink.hardlink_to(self.wheel)
        with self.assertRaises(RuntimeSafetyError):
            _install_built_artifacts(config)

    def test_foreign_or_unbound_private_state_cannot_install(self):
        self.state.mkdir()
        (self.state / "foreign.py").write_text("PRIVATE = True\n")
        with patch("subprocess.run", side_effect=AssertionError("must validate binding first")):
            with self.assertRaises(RuntimeSafetyError):
                _install_built_artifacts(self.config())

    def test_install_invocation_is_fixed_offline_and_has_no_inherited_credentials(self):
        original = subprocess.run
        with patch.dict(os.environ, {"HF_TOKEN": "synthetic", "AWS_SECRET_ACCESS_KEY": "synthetic",
                                    "PIP_INDEX_URL": "https://example.invalid", "LD_PRELOAD": "invalid"}):
            with patch("subprocess.run", wraps=original) as invoke:
                _install_built_artifacts(self.config())
        args, kwargs = invoke.call_args
        command = args[0]
        self.assertEqual(command[:4], [sys.executable, "-I", "-m", "pip"])
        for flag in ("--no-index", "--no-deps", "--no-cache-dir", "--no-input", "--no-compile"):
            self.assertIn(flag, command)
        self.assertEqual(command[-1], str(self.wheel))
        self.assertEqual(set(kwargs["env"]), {"PATH", "PIP_CONFIG_FILE", "PIP_DISABLE_PIP_VERSION_CHECK", "TMPDIR"})
        self.assertTrue(Path(kwargs["cwd"]).is_relative_to(self.state))
        self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)

    def test_interrupted_install_can_resume_before_any_plugin_is_imported(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("fixed pip", 1)):
            with self.assertRaises(subprocess.TimeoutExpired):
                _install_built_artifacts(self.config())
        self.assertEqual(read_json(self.state / "private-build-install.json")["phase"], "installing")
        self.assertNotIn(self.module, sys.modules)
        self.assertEqual(_load_plugin(self.config(epoch=2)).VALUE, 41)

    def test_contract_rejects_arbitrary_build_roots_and_unsafe_wheel_names(self):
        payload = self.config().to_dict()
        for field, value in (("build_dir", "/other-job/build"), ("built_artifacts", {
            "../foreign.whl": self.artifact}), ("built_artifacts", {
            self.filename: {**self.artifact, "size_bytes": True}})):
            with self.subTest(field=field), self.assertRaises(ValueError):
                RuntimeConfig.model_validate({**payload, "build_dir": "/job/build", field: value})


if __name__ == "__main__":
    unittest.main()
