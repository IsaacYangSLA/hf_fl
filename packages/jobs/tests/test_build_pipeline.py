"""Actual private build products are installed and consumed by FL workers.

LocalStore is solely the test transport. Live build-hook tests use the explicitly
qualified node executor when JOBS_BUILD_TEST_PROFILE/IMAGE are configured.
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
from hf2l_jobs.collection import SafeCollector
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
        with SafeCollector(artifacts) as collector:
            result = BuildResult.model_validate(json.loads(collector.read("build.json"))).validate_binding(self.build)
            body = collector.read(result.wheel.filename, max_bytes=result.wheel.size_bytes)
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

    def test_actual_manager_collection_stage_is_private_charged_once_and_survives_replay(self):
        from test_source_provisioning import ProvisioningHTTPTests, git
        from hf2l_jobs.models import Job, Project, Attempt
        from hf2l_jobs.executor import ExecutionIdentity
        from hf2l_jobs.resources import ResourceError
        from dataclasses import replace
        from hf2l_jobs.source import RegistryCatalog
        fixture = ProvisioningHTTPTests(methodName="test_real_sdk_managed_resources_and_repeat_are_idempotent")
        fixture.setUp()
        try:
            for existing in fixture.repository.iterdir():
                if existing.name != ".git" and existing.is_file():
                    existing.unlink()
            for existing in self.source.iterdir():
                (fixture.repository / existing.name).write_bytes(existing.read_bytes())
            git(fixture.repository, "add", ".")
            git(fixture.repository, "commit", "-qm", "offline build")
            fixture.commit = git(fixture.repository, "rev-parse", "HEAD")
            payload = self.spec.to_dict()
            payload.update(project_id="project", source_id="src",
                           source_commit=fixture.commit, runtime_image="runtime")
            for component in payload["components"]:
                component["resources"]["pool_id"] = "pool"
            fixture.spec = JobSpec.model_validate(payload)
            with fixture.database.transaction() as session:
                fixture.job = Job(id="build-job", project_id="project", creator_id="human",
                                  name=fixture.spec.name, spec_json=fixture.spec.to_dict(),
                                  spec_hash=fixture.spec.digest, target_round=fixture.spec.target_round,
                                  deadline_at=fixture.job.deadline_at, state="PROVISIONING",
                                  current_attempt=1, epoch=1)
                session.add(fixture.job)
                session.flush()
                fixture.attempt = Attempt(id="build-attempt", job_id=fixture.job.id, number=1, epoch=1)
                session.add(fixture.attempt)
            fixture.provisioner.registry = RegistryCatalog(
                fixture.registry(), {"runtime": "sha256:" + "b" * 64},
                dataset_bindings={"synthetic": {"alice", "bob"}})
            fixture.provisioner.build_approvals = {"build": {
                "project_subdir": ".", "approved_dependencies": {"build": metadata.version("build")}}}
            blob_bytes = fixture.prepay_blob()
            bundle = fixture.provisioner.ensure(fixture.job, fixture.attempt)
            config = BuildConfig.model_validate(fixture.provisioner.prepared_component(
                fixture.job, fixture.attempt, "build")).model_copy(update={
                    "source_dir": str(bundle.source_path),
                    "state_dir": str(bundle.component_paths["build"].state)})
            self.assertEqual(run_worker(config), 0)
            with SafeCollector(config.state_dir) as collector:
                retained = collector.retain(fixture.root / "retained" / ExecutionIdentity(
                    fixture.job.id, fixture.attempt.id, "build", fixture.attempt.epoch).key)
            wheel_descriptor = next(item for item in retained if item.path.endswith(".whl"))
            foreign = fixture.root / "foreign.whl"
            foreign.write_bytes(Path(wheel_descriptor.locator).read_bytes())
            unowned = tuple(replace(item, locator=str(foreign)) if item is wheel_descriptor else item for item in retained)
            with self.assertRaises(ResourceError):
                fixture.provisioner.prepare_build_outputs(fixture.job, fixture.attempt, {"build": unowned})
            prepared = fixture.provisioner.prepare_build_outputs(fixture.job, fixture.attempt, {"build": retained})
            product = Path(prepared["path"])
            self.assertEqual(product.stat().st_mode & 0o222, 0)
            self.assertEqual(set(p.name for p in product.iterdir()), set(prepared["built_artifacts"]))
            before = fixture.provisioner.prepared_component(fixture.job, fixture.attempt, "owner")
            self.assertEqual(before["built_artifacts"], prepared["built_artifacts"])
            transported = fixture.provisioner.prepared_build_products(fixture.job, fixture.attempt, "owner")
            self.assertEqual(set(transported), set(before["built_artifacts"]))
            for name, opaque in transported.items():
                self.assertIsInstance(opaque, bytes)
                self.assertEqual({"sha256": hashlib.sha256(opaque).hexdigest(), "size_bytes": len(opaque)},
                                 before["built_artifacts"][name])
            self.assertEqual(fixture.provisioner.prepared_build_products(fixture.job, fixture.attempt, "build"), {})
            self.assertNotIn(str(fixture.root), json.dumps(before))
            fixture.provisioner.ensure(fixture.job, fixture.attempt)
            after = fixture.provisioner.prepared_component(fixture.job, fixture.attempt, "owner")
            self.assertEqual(after["built_artifacts"], before["built_artifacts"])
            repeated = fixture.provisioner.prepare_build_outputs(fixture.job, fixture.attempt, {"build": retained})
            self.assertEqual(repeated, prepared)
            with fixture.database.transaction(immediate=False) as session:
                charged = session.get(Project, "project").retained_bytes
            source_resources = fixture.provisioner.ledger.resources(fixture.job.id, kind="source")
            self.assertEqual(len(source_resources), 1)
            self.assertEqual(source_resources[0]["details"]["pool_id"], "pool")
            build_resources = fixture.provisioner.ledger.resources(fixture.job.id, kind="build_products")
            self.assertEqual(len(build_resources), 1)
            build_resource = build_resources[0]
            logical_bytes = sum(item["size_bytes"] for item in prepared["built_artifacts"].values())
            physical_bytes = product.stat().st_blocks * 512
            physical_bytes += sum(item.stat().st_blocks * 512 for item in product.iterdir())
            self.assertEqual(build_resource["details"]["logical_bytes"], logical_bytes)
            self.assertEqual(build_resource["size_bytes"], physical_bytes)
            self.assertGreater(build_resource["size_bytes"], logical_bytes)
            self.assertGreaterEqual(build_resource["details"]["retention_reservation_bytes"], physical_bytes)
            self.assertEqual(charged, source_resources[0]["size_bytes"] + physical_bytes + blob_bytes)
            product_file = product / next(iter(prepared["built_artifacts"]))
            product_file.chmod(0o600)
            product_file.write_bytes(product_file.read_bytes() + b"changed")
            with self.assertRaises(ResourceError):
                fixture.provisioner.ensure(fixture.job, fixture.attempt)
        finally:
            fixture.tearDown()

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


@unittest.skipUnless(os.environ.get("JOBS_BUILD_TEST_PROFILE") and os.environ.get("JOBS_BUILD_TEST_IMAGE"),
                     "Live build isolation requires an explicitly qualified executor/image")
class QualifiedBuildHookIsolationTests(unittest.TestCase):
    def test_actual_runsc_build_hooks_cannot_read_other_job_or_reach_host_network(self):
        from hf2l_jobs.executor import ExecutionIdentity, ExecutionSpec, LinuxExecutor, ResourceLimits
        import time

        profile_path = Path(os.environ["JOBS_BUILD_TEST_PROFILE"])
        profile = json.loads(profile_path.read_text())
        owned = Path(profile["owned_root"])
        suffix = uuid4().hex[:12]
        executor_root = owned / ("build-adversarial-" + suffix)
        executor = LinuxExecutor(profile_path, executor_root)
        image = os.environ["JOBS_BUILD_TEST_IMAGE"]
        dependencies = json.loads(os.environ.get("JOBS_BUILD_TEST_DEPENDENCIES", '{"build":"1.6.1"}'))
        identities = {key: ExecutionIdentity("build-probe-" + key + "-" + suffix,
                                            "attempt-" + suffix, "build", 1) for key in ("a", "b")}
        jobs = {key: owned / "jobs" / identities[key].job_id for key in identities}
        sibling_source = jobs["b"] / "source/private.txt"
        sibling_cache = executor_root / identities["b"].key / "state/cache/private.txt"
        foreign_paths = [str(sibling_source), str(sibling_cache), profile["docker_host"].removeprefix("unix://"),
                         "/var/run/docker.sock", "/run/hf2l/proxy.sock", "/run/hf2l/secrets.json"]
        attack = """
import json
import os
import socket
def attack():
    checks = {}
    for name in ("HF_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "HF2L_JOBS_DATABASE_URL", "GIT_ASKPASS"):
        checks["credential_" + name] = name not in os.environ
    for index, name in enumerate(FOREIGN):
        try:
            pathlib.Path(name).read_bytes()
        except OSError:
            checks["foreign_file_" + str(index)] = True
        else:
            checks["foreign_file_" + str(index)] = False
    for index, name in enumerate((FOREIGN[2], "/var/run/docker.sock", "/run/hf2l/proxy.sock")):
        connection = socket.socket(socket.AF_UNIX)
        connection.settimeout(0.3)
        try:
            connection.connect(name)
        except OSError:
            checks["foreign_socket_" + str(index)] = True
        else:
            checks["foreign_socket_" + str(index)] = False
        finally:
            connection.close()
    for address, port, label in (("127.0.0.1", 22, "host"), ("169.254.169.254", 80, "metadata"), ("1.1.1.1", 443, "internet")):
        connection = socket.socket(socket.AF_INET)
        connection.settimeout(0.3)
        try:
            connection.connect((address, port))
        except OSError:
            checks["network_" + label] = True
        else:
            checks["network_" + label] = False
        finally:
            connection.close()
    try:
        pathlib.Path("/job/source/attempted-write.txt").write_text("must be readonly")
    except OSError:
        checks["source_readonly"] = True
    else:
        checks["source_readonly"] = False
    cache = pathlib.Path("/job/state/cache")
    cache.mkdir(exist_ok=True)
    marker = cache / "private.txt"
    checks["private_cache_starts_empty"] = not marker.exists()
    marker.write_text("job-a-private")
    checks["private_cache_owned"] = marker.read_text() == "job-a-private"
    pathlib.Path("/job/state/artifacts/isolation.json").write_text(json.dumps(checks))
    if not all(checks.values()):
        raise RuntimeError("sandbox build crossed its job boundary")
"""
        attack = "FOREIGN = " + repr(foreign_paths) + "\n" + attack
        observations, reports, collected, cleanup, checks = {}, {}, {}, {}, {}
        reserved = []
        try:
            for key, identity in identities.items():
                source = jobs[key] / "source"
                state = jobs[key] / "components/build/state"
                source.mkdir(mode=0o700, parents=True)
                state.mkdir(mode=0o700, parents=True)
                (source / "pyproject.toml").write_text(
                    '[build-system]\nrequires = []\nbuild-backend = "offline_hook"\nbackend-path = ["."]\n')
                body = wheel_backend("sandbox_private_" + key, "VALUE = " + repr(key) + "\n")
                if key == "a":
                    body = attack + body.replace("    name = ", "    attack()\n    name = ", 1)
                else:
                    body = "import time\n" + body.replace(
                        "    return []\n",
                        "    pathlib.Path('/job/state/cache').mkdir(exist_ok=True)\n"
                        "    pathlib.Path('/job/state/cache/private.txt').write_text('job-b-private')\n"
                        "    time.sleep(5)\n    return []\n", 1)
                    (source / "private.txt").write_text("job-b-source-secret")
                (source / "offline_hook.py").write_text(body)
                spec = example_spec("sandbox_private_" + key).model_copy(update={"runtime_image": image})
                config = BuildConfig(job_id=identity.job_id, attempt_id=identity.attempt_id,
                                     component_id=identity.component_id, epoch=identity.epoch,
                                     spec=spec, spec_digest=spec.digest, source_manifest=immutable_manifest(source),
                                     approved_dependencies=dependencies)
                config_path = jobs[key] / "attempts" / identity.attempt_id / "build/runtime.json"
                config_path.parent.mkdir(mode=0o700, parents=True)
                config_path.write_text(json.dumps(config.to_dict()))
                config_path.chmod(0o400)
                execution = ExecutionSpec(
                    identity=identity, image_digest=image, source_path=str(source), state_path=str(state),
                    argv=("python", "-m", "hf2l_jobs.runtime", "--config", "/run/hf2l/runtime.json"),
                    proxy_endpoint=None, resources=ResourceLimits(500, 512 * 1024**2, 128 * 1024**2),
                    config_path=str(config_path), role="build", pool_id="cpu", deadline=time.time() + 90)
                self.assertTrue(executor.reserve(execution).acknowledged)
                reserved.append(identity)
            executor.start(identities["b"])
            executor.start(identities["a"])
            deadline = time.monotonic() + 75
            while time.monotonic() < deadline:
                observations = {key: executor.inspect(identity) for key, identity in identities.items()}
                if all(item.termination_confirmed for item in observations.values()):
                    break
                time.sleep(0.2)
            for key, observation in observations.items():
                self.assertTrue(observation.termination_confirmed, key)
                collected[key] = executor.collect(identities[key])
                if observation.exit_code != 0:
                    logs = next((item for item in collected[key] if item.path == "runtime/stdout.log"), None)
                    diagnostic = Path(logs.locator).read_text() if logs else ""
                    self.fail(key + " exited " + str(observation.exit_code) + ": " + diagnostic)
                build_report = next(item for item in collected[key] if item.path == "artifacts/build.json")
                reports[key] = BuildResult.model_validate(json.loads(Path(build_report.locator).read_text())).to_dict()
            isolation = next(item for item in collected["a"] if item.path == "artifacts/isolation.json")
            checks = json.loads(Path(isolation.locator).read_text())
            self.assertGreaterEqual(len(checks), 19)
            self.assertTrue(all(checks.values()), checks)
            sibling_marker = next(item for item in collected["b"] if item.path == "cache/private.txt")
            self.assertEqual(Path(sibling_marker.locator).read_text(), "job-b-private")
            self.assertEqual(sibling_source.read_text(), "job-b-source-secret")
        finally:
            for identity in reserved:
                try:
                    if not executor.inspect(identity).termination_confirmed:
                        executor.stop(identity, grace_seconds=1)
                    cleanup[identity.job_id] = executor.release(identity)
                except Exception as exc:
                    cleanup[identity.job_id] = {"error": type(exc).__name__}
            executor_root.mkdir(mode=0o700, parents=True, exist_ok=True)
            (executor_root / "evidence.json").write_text(json.dumps({
                "profile": str(profile_path), "image": image,
                "dependencies": dependencies, "build_results": reports,
                "isolation_checks": checks, "cleanup": cleanup}, indent=2))
        self.assertTrue(all(value is True for value in cleanup.values()), cleanup)


if __name__ == "__main__":
    unittest.main()
