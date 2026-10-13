"""Generic immutable runtime inputs and bounded qualification diagnostics."""
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from deploy.jobs.runtime.build_image import digest, reuse_project_wheels
from deploy.jobs.runtime import build_image


class RuntimeHelperTests(unittest.TestCase):
    def test_synthetic_copy_input_remains_readable_under_private_umask(self):
        import os
        import stat
        import tarfile
        from deploy.jobs.runtime.qualify_readonly_io import write_canary_file
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = os.umask(0o077)
            try:
                source = root / "blob"
                write_canary_file(source, 4096)
            finally:
                os.umask(previous)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            self.assertEqual(source.stat().st_size, 4096)
            self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o644)
            with tarfile.open(root / "copy-input.tar", "w") as archive:
                archive.add(source, arcname="blob")
            with tarfile.open(root / "copy-input.tar") as archive:
                # Docker COPY preserves this mode while assigning root ownership.
                self.assertEqual(archive.getmember("blob").mode, 0o644)

    def test_terminal_canary_failure_preserves_bounded_logs_before_cleanup(self):
        from types import SimpleNamespace
        from deploy.jobs.runtime.qualify_readonly_io import Qualification
        qualifier = Qualification.__new__(Qualification)
        qualifier.report = {}
        def docker(*args, **kwargs):
            if args[0] == "logs":
                return SimpleNamespace(returncode=0, stdout='{"ready": true}\n',
                                       stderr="PermissionError: synthetic image input denied")
            if args[0] == "inspect":
                return SimpleNamespace(returncode=0, stdout=json.dumps([{
                    "State": {"Running": False, "Pid": 0, "ExitCode": 1, "OOMKilled": False}}]))
            raise AssertionError(args)
        qualifier.docker_call = docker
        with self.assertRaisesRegex(RuntimeError, "exited before"):
            qualifier.wait_log("owned-probe", '"finished": true')
        evidence = qualifier.report["probe_failures"][0]
        self.assertEqual(evidence["state"]["ExitCode"], 1)
        self.assertIn("PermissionError", evidence["stderr"])
        self.assertIn('"ready": true', evidence["stdout"])

    def test_frozen_wheels_reused_and_tampering_refused_before_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            frozen, output = root / "wheels", root / "output"
            frozen.mkdir()
            output.mkdir()
            records = []
            for name in ["hf2l", "hf2l_exchange", "hf2l_jobs"]:
                wheel = frozen / (name + "-1.0-py3-none-any.whl")
                with zipfile.ZipFile(wheel, "w") as archive:
                    archive.writestr(name + "-1.0.dist-info/METADATA",
                                     "Metadata-Version: 2.1\nName: " + name + "\nVersion: 1.0\n")
                records.append({"filename": wheel.name, "sha256": digest(wheel)})
            (frozen / "manifest.json").write_text(json.dumps({"wheels": records}))
            reuse_project_wheels(frozen, output)
            self.assertEqual({p.name for p in output.iterdir()}, {r["filename"] for r in records})
            for path in output.iterdir():
                path.unlink()
            last = frozen / records[-1]["filename"]
            with last.open("ab") as stream:
                stream.write(b"tampering")
            with self.assertRaisesRegex(ValueError, "SHA256"):
                reuse_project_wheels(frozen, output)
            self.assertEqual(list(output.iterdir()), [])
    def test_invalid_frozen_source_identity_rejected_before_build(self):
        for commit in ("HEAD", "a" * 39, "A" * 40, "../source"):
            with self.subTest(commit=commit), patch.object(build_image.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "full Git identity"):
                    build_image.main(["--output-dir", "/unused/runtime-build", "--base-image", "sha256:" + "c" * 64, "--source-commit", commit])
                run.assert_not_called()

    def test_source_mismatch_or_dirty_checkout_rejected_before_build(self):
        expected = "a" * 40
        for identity, status in (("b" * 40, ""), (expected, " M source.py"),
                                 (expected, "?? untracked.py"), (expected, "!! ignored.py")):
            with self.subTest(identity=identity, status=status):
                replies = [SimpleNamespace(stdout=identity), SimpleNamespace(stdout=status)]
                with patch.object(build_image.subprocess, "run", side_effect=replies) as run:
                    with self.assertRaisesRegex(ValueError, "frozen release commit"):
                        build_image.main(["--output-dir", "/unused/runtime-build", "--base-image", "sha256:" + "c" * 64, "--source-commit", expected])
                    self.assertEqual(run.call_count, 2)
                    status_command = run.call_args_list[1].args[0]
                    self.assertIn("--untracked-files=all", status_command)
                    self.assertIn("--ignored", status_command)

    def test_wheel_identity_manifest_coverage_required_before_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            frozen, output = Path(tmp) / "wheels", Path(tmp) / "output"
            frozen.mkdir()
            output.mkdir()
            for name in ("hf2l", "hf2l_exchange", "foreign_package"):
                wheel = frozen / (name + "-1.0-py3-none-any.whl")
                with zipfile.ZipFile(wheel, "w") as archive:
                    archive.writestr(name + "-1.0.dist-info/METADATA",
                                     "Metadata-Version: 2.1\nName: " + name + "\nVersion: 1.0\n")
            with self.assertRaisesRegex(ValueError, "exactly the three"):
                reuse_project_wheels(frozen, output)
            self.assertEqual(list(output.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
