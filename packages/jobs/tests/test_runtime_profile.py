"""Runtime republishing must preserve valid I/O evidence and refuse corruption."""
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

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

    def test_new_policy_preserves_only_matching_complete_affinity_identity(self):
        policy = {"runtime_environment": {"GOMAXPROCS": "2"},
                  "runtime_cpu_affinity": list(range(2)),
                  "runtime_cpu_count": 2,
                  "runtime_cpu_policy": str(self.root / "runtime-policy.json"),
                  "runtime_cpu_policy_sha256": "f" * 64,
                  "containerd_unit": "private-containerd.service"}
        # Historical I/O evidence cannot qualify the newly bound policy.
        self.profile.update(policy)
        self.assertNotIn("backing_io_qualified", self.promote())
        self.previous.update(policy)
        self.report["runtime_identity"].update(policy)
        self.write_evidence()
        self.assertTrue(self.promote()["backing_io_qualified"])
        self.profile["runtime_cpu_affinity"] = [2, 3]
        self.assertNotIn("backing_io_qualified", self.promote())

    def test_cpu_count_change_requires_fresh_supplemental_qualification(self):
        policy = {"runtime_environment": {"GOMAXPROCS": "2"},
                  "runtime_cpu_affinity": [4], "runtime_cpu_count": 2,
                  "runtime_cpu_policy": str(self.root / "runtime-policy.json"),
                  "runtime_cpu_policy_sha256": "f" * 64,
                  "containerd_unit": "private-containerd.service"}
        self.profile.update(policy)
        self.previous.update(policy)
        self.report["runtime_identity"].update(policy)
        self.write_evidence()
        self.assertTrue(self.promote()["backing_io_qualified"])
        self.profile["runtime_cpu_count"] = 3
        self.assertNotIn("backing_io_qualified", self.promote())

    def test_incomplete_new_policy_is_controlled_refusal(self):
        self.profile.update(runtime_environment={"GOMAXPROCS": "2"},
                            runtime_cpu_affinity=list(range(6)))
        with self.assertRaisesRegex(ValueError, "identity is incomplete"):
            self.promote()

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


class RuntimeCpuPolicyTests(unittest.TestCase):
    def test_invalid_counts_are_refused(self):
        for count in (0, -1, True, 1.5, "2"):
            with self.subTest(count=count), self.assertRaisesRegex(ValueError, "positive integer"):
                SETUP.runtime_cpu_affinity(count)

    def test_small_hosts_and_sparse_masks_are_supported(self):
        for available, count, expected in (({7}, 2, [7]), ({2, 9}, 6, [2, 9]),
                                            ({3, 8, 10, 14}, 2, [3, 8])):
            with self.subTest(available=available), patch.object(SETUP.os, "sched_getaffinity", return_value=available):
                self.assertEqual(SETUP.runtime_cpu_affinity(count), expected)

    def test_no_available_cpu_is_refused(self):
        with patch.object(SETUP.os, "sched_getaffinity", return_value=set()):
            with self.assertRaisesRegex(ValueError, "at least one"):
                SETUP.runtime_cpu_affinity()

    def test_persisted_mask_does_not_follow_control_client_affinity_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(SETUP.os, "sched_getaffinity", return_value={3, 8, 10}):
                first = SETUP.runtime_cpu_policy(root, 2, create=True)
                self.assertEqual(first["runtime_cpu_affinity"], [3, 8])
                self.assertEqual((root / "runtime-policy.json").stat().st_mode & 0o777, 0o600)
            with patch.object(SETUP.os, "sched_getaffinity", return_value={0, 3, 8, 10}):
                self.assertEqual(SETUP.runtime_cpu_policy(root), first)
                with self.assertRaisesRegex(ValueError, "existing CPU policy differs"):
                    SETUP.runtime_cpu_policy(root, 3, create=True)
            with patch.object(SETUP.os, "sched_getaffinity", return_value={3}):
                with self.assertRaisesRegex(ValueError, "unavailable"):
                    SETUP.runtime_cpu_policy(root)

    def test_missing_malformed_and_public_policies_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "runtime-policy.json"
            with self.assertRaisesRegex(ValueError, "missing"):
                SETUP.runtime_cpu_policy(root)
            for policy in ([], {"cpu_count": True, "cpu_affinity": [1]},
                           {"cpu_count": 1, "cpu_affinity": [1, 2]},
                           {"cpu_count": 2, "cpu_affinity": []},
                           {"cpu_count": 2, "cpu_affinity": [1, 1]},
                           {"cpu_count": 2, "cpu_affinity": [True]}):
                with self.subTest(policy=policy):
                    path.write_text(json.dumps(policy))
                    path.chmod(0o600)
                    with self.assertRaisesRegex(ValueError, "invalid"):
                        SETUP.runtime_cpu_policy(root)
            path.write_text(json.dumps({"cpu_count": 1, "cpu_affinity": [1]}))
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "private regular"):
                SETUP.runtime_cpu_policy(root)


class RuntimeQualificationCpuPolicyTests(unittest.TestCase):
    def test_qualification_uses_persisted_policy_and_rejects_changed_effective_mask(self):
        spec = importlib.util.spec_from_file_location(
            "hf2l_runtime_test_qualification", SOURCE.with_name("qualify.py"))
        qualifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(qualifier)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "runsc"
            binary.write_bytes(b"synthetic runtime binary")
            pidfile = root / "daemon.pid"
            pidfile.write_text("123")
            config = root / "daemon.json"
            config.write_text(json.dumps({
                "pidfile": str(pidfile), "data-root": str(root / "data"),
                "runtimes": {"runsc": {"path": str(binary), "runtimeArgs": [
                    "--network=sandbox", "--host-uds=open", "--platform=systrap"]}}}))
            probe = qualifier.Qualification.__new__(qualifier.Qualification)
            probe.args = SimpleNamespace(daemon_config=str(config), image="synthetic")
            probe.report = {"checks": []}
            image_id = "sha256:" + "a" * 64
            probe.docker_json = lambda *args: ([{"Id": image_id}] if args[0] == "image" else {
                "Runtimes": {"runsc": {}}, "CgroupVersion": "2", "DockerRootDir": str(root / "data")})
            def command(argv):
                if "--property=Environment" in argv:
                    stdout = "GOMAXPROCS=2"
                elif "--property=MainPID" in argv:
                    stdout = "123" if "dockerd" in argv[4] else "124"
                elif argv[0] == "readlink":
                    stdout = "net:host"
                elif "readlink" in argv:
                    stdout = "net:private"
                else:
                    stdout = "synthetic runtime version"
                return SimpleNamespace(returncode=0, stdout=stdout)
            with patch.object(qualifier, "run", side_effect=command), \
                    patch.object(SETUP.os, "sched_getaffinity", return_value={7}):
                policy = SETUP.runtime_cpu_policy(root, 6, create=True)
                probe.configure()
                self.assertEqual(probe.report["runtime"]["runtime_cpu_count"], 6)
                self.assertEqual(probe.report["runtime"]["runtime_cpu_affinity"], [7])
                self.assertEqual(probe.report["runtime"]["runtime_cpu_policy_sha256"],
                                 policy["runtime_cpu_policy_sha256"])
            probe.report = {"checks": []}
            with patch.object(qualifier, "run", side_effect=command), \
                    patch.object(SETUP.os, "sched_getaffinity",
                                 side_effect=lambda pid: {8} if pid == 124 else {7}):
                with self.assertRaisesRegex(RuntimeError, "configuration is unavailable"):
                    probe.configure()


if __name__ == "__main__":
    unittest.main()
