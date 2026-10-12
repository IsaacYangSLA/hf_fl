"""Runtime republishing must preserve valid I/O evidence and refuse corruption."""
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[3] / "deploy/jobs/runtime/setup.py"
SPEC = importlib.util.spec_from_file_location("hf2l_runtime_profile_setup", SOURCE)
SETUP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SETUP)


class RuntimeProfilePromotionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.path = self.root / "profile.json"
        self.report_path = self.root / "qualification.json"
        self.profile = {
            "owned_root": str(self.root), "docker_host": "unix:///node/docker.sock",
            "docker_data_root": "/node/data", "containerd_socket": "/node/containerd.sock",
            "daemon_config": "/node/daemon.json", "daemon_config_sha256": "a" * 64,
            "daemon_unit": "private-runtime.service", "runsc_sha256": "b" * 64,
            "runtime_files_sha256": {"/opt/private/runsc": "b" * 64},
            "sandbox_uid": os.getuid(), "sandbox_gid": os.getgid(),
            "profile": "runsc-cpu-v1", "runtime": "runsc", "network": "none",
            "runsc_network": "sandbox", "runsc_host_uds": "open",
            "proxy_transport": "unix", "bounded_volumes": "loop-ext4", "read_only": True,
            "qualification_sha256": "c" * 64,
        }
        self.devices = [{"path": "/dev/sda", "major": 8, "minor": 0,
                         "sysfs_path": "/sys/devices/pci/block/sda"}]
        self.report = {
            "qualified": True, "checks": [{"name": "uncached-device-read", "passed": True}],
            "runtime_identity": {k: v for k, v in self.profile.items() if k != "qualification_sha256"},
            "base_qualification_sha256": self.profile["qualification_sha256"],
            "backing_devices": self.devices, "completed_at": "2026-10-10T00:00:00+00:00",
        }
        self.previous = deepcopy(self.profile)
        self.previous.update(backing_io_qualified=True, backing_devices=self.devices,
                             backing_io_qualification_path=str(self.report_path))
        self.write_evidence()

    def write_evidence(self):
        content = json.dumps(self.report).encode()
        self.report_path.write_bytes(content)
        self.report_path.chmod(0o600)
        self.previous["backing_io_qualification_sha256"] = hashlib.sha256(content).hexdigest()
        self.path.write_text(json.dumps(self.previous))
        self.path.chmod(0o600)

    def promote(self):
        return SETUP.preserve_readonly_qualification(self.path, deepcopy(self.profile))

    def test_matching_report_is_preserved(self):
        result = self.promote()
        self.assertIs(result["backing_io_qualified"], True)
        self.assertEqual(result["backing_devices"], self.devices)
        self.assertEqual(result["backing_io_qualification_checks"], 1)
        self.assertEqual(result["backing_io_qualification_sha256"],
                         self.previous["backing_io_qualification_sha256"])
        self.assertEqual(result["backing_io_qualified_at"], self.report["completed_at"])

    def test_first_publication_has_no_supplemental_claim(self):
        self.path.unlink()
        self.assertNotIn("backing_io_qualified", self.promote())

    def test_original_profile_without_attestation_stays_unqualified_for_io(self):
        self.previous.pop("backing_io_qualified")
        self.write_evidence()
        self.assertNotIn("backing_io_qualified", self.promote())

    def test_runtime_or_policy_change_requires_new_qualification(self):
        for key in self.report["runtime_identity"]:
            with self.subTest(key=key):
                value = deepcopy(self.profile)
                value[key] = "different"
                self.assertNotIn("backing_io_qualified",
                    SETUP.preserve_readonly_qualification(self.path, value))

    def test_changed_base_report_requires_new_qualification(self):
        self.profile["qualification_sha256"] = "d" * 64
        self.assertNotIn("backing_io_qualified", self.promote())

    def test_changed_evidence_refused_without_profile_mutation(self):
        before = self.path.read_bytes()
        self.report_path.write_text("{}")
        with self.assertRaisesRegex(ValueError, "evidence changed"):
            self.promote()
        self.assertEqual(self.path.read_bytes(), before)

    def test_failed_check_and_failed_report_refused(self):
        for change in ({"qualified": False},
                       {"checks": [{"name": "read", "passed": False}]}, {"checks": []}):
            with self.subTest(change=change):
                self.report.update(change)
                self.write_evidence()
                with self.assertRaises(ValueError):
                    self.promote()

    def test_report_runtime_binding_mismatch_refused(self):
        self.report["runtime_identity"]["docker_data_root"] = "/foreign/data"
        self.write_evidence()
        with self.assertRaises(ValueError):
            self.promote()

    def test_report_base_binding_mismatch_refused(self):
        self.report["base_qualification_sha256"] = "d" * 64
        self.write_evidence()
        with self.assertRaises(ValueError):
            self.promote()

    def test_report_device_binding_mismatch_refused(self):
        self.report["backing_devices"] = []
        self.write_evidence()
        with self.assertRaises(ValueError):
            self.promote()

    def test_unsafe_device_and_duplicate_device_refused(self):
        for devices in ([{"path": "/tmp/file", "major": 8, "minor": 0,
                          "sysfs_path": "/sys/devices/sda"}],
                        [self.devices[0], self.devices[0]]):
            with self.subTest(devices=devices):
                self.previous["backing_devices"] = devices
                self.report["backing_devices"] = devices
                self.write_evidence()
                with self.assertRaises(ValueError):
                    self.promote()

    def test_report_permissions_and_hardlinks_refused(self):
        self.report_path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.promote()
        self.report_path.chmod(0o600)
        os.link(self.report_path, self.root / "report-copy")
        with self.assertRaises(ValueError):
            self.promote()

    def test_symlinked_report_ancestor_refused(self):
        target = self.root / "actual"
        target.mkdir()
        target.chmod(0o700)
        original = target / "report.json"
        original.write_bytes(self.report_path.read_bytes())
        original.chmod(0o600)
        link = self.root / "linked"
        link.symlink_to(target, target_is_directory=True)
        self.previous["backing_io_qualification_path"] = str(link / "report.json")
        self.path.write_text(json.dumps(self.previous))
        with self.assertRaises(ValueError):
            self.promote()

    def test_profile_symlink_and_public_permissions_refused(self):
        original = self.root / "real-profile"
        self.path.rename(original)
        self.path.symlink_to(original)
        with self.assertRaises(ValueError):
            self.promote()
        self.path.unlink()
        original.rename(self.path)
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.promote()


if __name__ == "__main__":
    unittest.main()
