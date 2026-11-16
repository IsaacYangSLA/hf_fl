"""Actual private build products are installed and consumed by FL workers.

LocalStore is solely the test transport. Native executor isolation is qualified
by the separate Go executor integration gate.
"""
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
from uuid import uuid4

from hf2l_jobs.build import BuildArtifact, BuildConfig, BuildResult, BuildSafetyError, run_worker
from hf2l_jobs.domain import JobSpec
from hf2l_jobs.workflow import RuntimeConfig


def wheel_backend(module, module_source):
    return (
        "import pathlib\nimport zipfile\n"
        "def get_requires_for_build_wheel(config_settings=None):\n    return []\n"
        "def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):\n"
        "    name = 'hf2l_private_built-0.1-py3-none-any.whl'\n"
        "    files = " + repr({
            module + ".py": module_source,
            "hf2l_private_built-0.1.dist-info/METADATA": "Metadata-Version: 2.1\nName: hf2l-private-built\nVersion: 0.1\n",
            "hf2l_private_built-0.1.dist-info/WHEEL": "Wheel-Version: 1.0\nGenerator: approved-offline-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
            "hf2l_private_built-0.1.dist-info/RECORD": "",
        }) + "\n"
        "    with zipfile.ZipFile(pathlib.Path(wheel_directory) / name, 'w') as archive:\n"
        "        for path, content in files.items():\n            archive.writestr(path, content)\n"
        "    return name\n"
    )


def immutable_manifest(root):
    return {item.relative_to(root).as_posix(): hashlib.sha256(item.read_bytes()).hexdigest()
            for item in root.rglob("*") if item.is_file()}


def example_spec(module):
    resources = {"pool_id": "cpu", "cpu_millicores": 1000,
                 "memory_bytes": 1 << 30, "disk_bytes": 1 << 30}
    return JobSpec.model_validate({
        "project_id": "test", "name": "Built private plugin", "source_id": "approved",
        "source_commit": "a" * 40, "runtime_image": "approved-runtime",
        "plugin": module, "options": {"seed": 7, "epochs": 1, "synthetic_examples": 8,
                                    "batch_size": 4, "learning_rate": 0.02, "device": "cpu",
                                    "minimum_participants": 2},
        "participants": [{"participant_id": "alice", "dataset_binding": "synthetic"},
                         {"participant_id": "bob", "dataset_binding": "synthetic"}],
        "components": [{"component_id": "owner", "role": "owner", "resources": resources},
                       {"component_id": "build", "role": "build", "resources": resources}],
        "target_round": 1, "max_duration_seconds": 120})


class PrivateBuildPipelineTests(unittest.TestCase):
    def setUp(self):
        try:
            metadata.version("build")
        except metadata.PackageNotFoundError:
            if os.environ.get("JOBS_REQUIRE_RUNTIME_TESTS") == "1":
                raise
            self.skipTest("Offline build pipeline requires the approved build frontend")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.module = "hf2l_built_plugin_" + uuid4().hex
        self.spec = example_spec(self.module)
        (self.source / "pyproject.toml").write_text(
            '[build-system]\nrequires = []\nbuild-backend = "offline_hook"\nbackend-path = ["."]\n')
        (self.source / "offline_hook.py").write_text(wheel_backend(
            self.module, "from hf2l.plugins.lenet_poc import *\nBUILT_ONLY = True\n"))
        self.build = BuildConfig(job_id="job-a", attempt_id="attempt-a", component_id="build", epoch=1,
                                 spec=self.spec, spec_digest=self.spec.digest,
                                 source_dir=str(self.source), state_dir=str(self.root / "build-state"),
                                 source_manifest=immutable_manifest(self.source),
                                 approved_dependencies={"build": metadata.version("build")})

    def products(self):
        self.assertEqual(run_worker(self.build), 0)
        self.assertFalse((self.source / (self.module + ".py")).exists())
        artifacts = Path(self.build.state_dir) / "artifacts"
        result = BuildResult.model_validate(json.loads((artifacts / "build.json").read_text())).validate_binding(self.build)
        body = (artifacts / result.wheel.filename).read_bytes()
        self.assertEqual(len(body), result.wheel.size_bytes)
        self.assertEqual(hashlib.sha256(body).hexdigest(), result.wheel.sha256)
        products = self.root / "build-products"
        products.mkdir()
        path = products / result.wheel.filename
        path.write_bytes(body)
        path.chmod(0o400)
        return products, {result.wheel.filename: {
            "sha256": result.wheel.sha256, "size_bytes": result.wheel.size_bytes}}

    def config(self, built_artifacts, role="owner", participant=None):
        return RuntimeConfig.model_validate({
            "role": role, "job_id": "job-a", "attempt_id": "attempt-a", "component_id": "owner" if role == "owner" else "client-" + participant,
            "participant_id": participant, "space_id": "job-a", "epoch": 1,
            "spec": self.spec.to_dict(), "spec_digest": self.spec.digest,
            "source_dir": str(self.source), "state_dir": str(self.root / ("owner-state" if role == "owner" else "client-" + participant + "-state")),
            "source_manifest": dict(self.build.source_manifest),
            "participant_principals": {"alice": "alice", "bob": "bob"}, "dataset_bindings": {"synthetic": {"kind": "synthetic"}},
            "built_artifacts": built_artifacts,
        })

    def step(self, config, products):
        # Trusted fixture mirrors the sandbox's fixed /job/build mount locally.
        # The deployment contract itself accepts only /job/build.
        wrapper = {"config": config.to_dict(), "products": str(products), "storage": str(self.root / "storage")}
        script = """
import importlib
import json
from pathlib import Path
import sys
from hf2l_jobs.workflow import RuntimeConfig
from hf2l_jobs.runtime import run_worker, _load_plugin
from hf2l.backends.local import LocalStore
wrapper = json.loads(sys.argv[1])
config = RuntimeConfig.model_validate(wrapper["config"]).model_copy(update={"build_dir": wrapper["products"]})
with LocalStore(Path(wrapper["storage"]), config.participant_id or "owner") as store:
    status = run_worker(config, store=store, once=True)
module = _load_plugin(config)
assert module.BUILT_ONLY
assert Path(module.__file__).resolve().is_relative_to((Path(config.state_dir) / "site-packages").resolve())
raise SystemExit(status)
"""
        env = {**os.environ, "OMP_NUM_THREADS": "2", "MKL_NUM_THREADS": "2", "OPENBLAS_NUM_THREADS": "2"}
        return subprocess.run([sys.executable, "-c", script, json.dumps(wrapper)],
                              capture_output=True, text=True, timeout=90, env=env)

    def test_real_wheel_only_plugin_initializes_trains_and_aggregates(self):
        try:
            import torch
            import safetensors
        except ImportError:
            if os.environ.get("JOBS_REQUIRE_RUNTIME_TESTS") == "1":
                raise
            self.skipTest("Built-plugin FL integration requires sandbox training extras")
        products, artifacts = self.products()
        owner = self.config(artifacts)
        for config in (owner, self.config(artifacts, "client", "alice"),
                       self.config(artifacts, "client", "bob"), owner):
            result = self.step(config, products)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        from hf2l.backends.local import LocalStore
        from hf2l_jobs.runtime import _main_document
        with LocalStore(self.root / "storage", "owner") as store:
            document = _main_document(store, owner)[1]
        self.assertEqual(document["round"], 1)
        self.assertEqual({item["participant"] for item in document["submissions"]}, {"alice", "bob"})
        self.assertEqual(sum(item["num_examples"] for item in document["submissions"]), 16)
        self.assertTrue((Path(owner.state_dir) / "site-packages" / (self.module + ".py")).is_file())
        self.assertTrue((self.root / "client-alice-state/site-packages" / (self.module + ".py")).is_file())

    def test_altered_readonly_product_is_rejected_before_plugin_execution(self):
        products, artifacts = self.products()
        wheel = next(products.iterdir())
        wheel.chmod(0o600)
        wheel.write_bytes(wheel.read_bytes() + b"foreign bytes")
        result = self.step(self.config(artifacts), products)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "owner-state/site-packages").exists())


    def test_build_descriptors_reject_foreign_identity_paths_and_boolean_sizes(self):
        products, artifacts = self.products()
        result = BuildResult.model_validate(json.loads((Path(self.build.state_dir) / "artifacts/build.json").read_text()))
        foreign = result.to_dict()
        foreign["binding"]["job_id"] = "job-b"
        with self.assertRaises(BuildSafetyError):
            BuildResult.model_validate(foreign).validate_binding(self.build)
        for filename in ("../other.whl", "/other.whl", "a/b.whl", "x\\evil.whl"):
            with self.subTest(filename=filename), self.assertRaises(ValueError):
                BuildArtifact(filename=filename, sha256="a" * 64, size_bytes=1)
        with self.assertRaises(ValueError):
            BuildArtifact(filename="approved-0.1-py3-none-any.whl", sha256="a" * 64, size_bytes=True)


if __name__ == "__main__":
    unittest.main()
