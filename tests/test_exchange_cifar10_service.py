"""Native service-launch boundaries for the temporary CIFAR-10 example."""

from __future__ import annotations

import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch


_SOURCE = Path(__file__).resolve().parents[1] / "examples/exchange_cifar10/start_service.py"
_SPEC = importlib.util.spec_from_file_location("cifar10_native_service", _SOURCE)
assert _SPEC and _SPEC.loader
service = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(service)


class NativeServiceTests(unittest.TestCase):
    def test_explicit_native_executable_is_required(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            service.parse_args(["--work-dir", "/unused", "--emulated-storage"])

    def test_missing_executable_allocates_no_work_directory(self):
        with tempfile.TemporaryDirectory() as parent:
            work = Path(parent) / "work"
            args = service.parse_args([
                "--exchange-binary", str(Path(parent) / "absent"),
                "--work-dir", str(work), "--emulated-storage",
            ])
            with self.assertRaises(FileNotFoundError):
                service.run(args)
            self.assertFalse(work.exists())

    def test_nonexecutable_file_allocates_no_work_directory(self):
        with tempfile.TemporaryDirectory() as parent:
            binary = Path(parent) / "native-exchange"
            binary.write_text("not an executable")
            binary.chmod(0o600)
            work = Path(parent) / "work"
            args = service.parse_args([
                "--exchange-binary", str(binary),
                "--work-dir", str(work), "--emulated-storage",
            ])
            with self.assertRaisesRegex(ValueError, "executable native Go"):
                service.run(args)
            self.assertFalse(work.exists())

    def test_maintenance_dispatches_directly_to_native_executable(self):
        binary = Path("/reviewed/native/hf2l-exchange")
        processes = service.Processes(Path("/unused"), {}, threading.Event(), binary)
        child = SimpleNamespace(poll=lambda: 0, returncode=0)
        with patch.object(processes, "start", return_value=child) as start:
            processes.run_cli("check-db")
        start.assert_called_once_with(
            "check-db", [str(binary), "check-db"], background=False,
        )


if __name__ == "__main__":
    unittest.main()
