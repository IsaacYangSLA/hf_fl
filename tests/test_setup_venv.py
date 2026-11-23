"""Exercise interpreter selection and safe reuse in the source setup command."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import venv


_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "setup_venv.py"


class SetupEnvironmentTests(unittest.TestCase):
    def invoke(self, directory):
        return subprocess.run(
            [sys.executable, str(_SCRIPT), str(directory)],
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_setup_creates_then_reuses_the_selected_python(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "training env"
            created = self.invoke(target)
            self.assertEqual(created.returncode, 0, created.stderr)
            python = target / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            probe = subprocess.run(
                [str(python), "-I", "-c", "import pip,sys; print(sys.version.split()[0])"],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(probe.stdout.strip(), sys.version.split()[0])
            config = (target / "pyvenv.cfg").read_bytes()
            marker = target / "keep"
            marker.write_text("existing environment data", encoding="utf-8")
            reused = self.invoke(target)
            self.assertEqual(reused.returncode, 0, reused.stderr)
            self.assertEqual((target / "pyvenv.cfg").read_bytes(), config)
            self.assertEqual(marker.read_text(encoding="utf-8"), "existing environment data")

    def test_setup_does_not_populate_unrelated_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / ".venv"
            target.mkdir()
            marker = target / "keep"
            marker.touch()
            denied = self.invoke(target)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("move this directory aside", denied.stderr)
            self.assertEqual(list(target.iterdir()), [marker])

    @unittest.skipUnless(os.name == "posix", "requires POSIX symbolic links")
    def test_setup_refuses_symbolic_links(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / ".venv"
            missing = root / "missing"
            target.symlink_to(missing)
            denied = self.invoke(target)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("symbolic link", denied.stderr)
            self.assertTrue(target.is_symlink())
            self.assertFalse(missing.exists())

    def test_setup_does_not_repair_an_environment_without_pip(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / ".venv"
            venv.create(target, with_pip=False)
            config = (target / "pyvenv.cfg").read_bytes()
            denied = self.invoke(target)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("does not contain pip", denied.stderr)
            self.assertEqual((target / "pyvenv.cfg").read_bytes(), config)


if __name__ == "__main__":
    unittest.main()
