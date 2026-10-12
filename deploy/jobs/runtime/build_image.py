"""Stage verified wheels on the trusted host; build the worker image offline.

No job source or job build hook runs here. These are the deployment's trusted
HF2L distributions, composed with CPU Torch and exact dependency wheel hashes.
The resulting image still requires runtime isolation qualification and explicit
administrator approval before admission to a compute pool.
"""
from __future__ import annotations

import argparse
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid
import zipfile


BUILD_INPUTS = {"build": "1.6.1", "pyproject-hooks": "1.3.3", "wheel": "0.48.0"}
DEFAULT_BASE = "sha256:2e3f788256a7e2abe86eb972dd72d7bcdf4273f5d775817d2e3619170852559b"
ROOT = Path(__file__).resolve().parents[3]


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--output-dir", type=Path, required=True, help="Task-owned artifact parent outside the checkout")
    value.add_argument("--python", default="/usr/bin/python3.14", help="Trusted host CPython 3.14 interpreter")
    value.add_argument("--uv", default=str(Path.home() / ".local/bin/uv"), help="Trusted deployment UV executable")
    value.add_argument("--base-image", default=DEFAULT_BASE, help="Operator-verified local image ID")
    value.add_argument("--docker-host", help="Private task-owned Docker unix socket")
    value.add_argument("--stage-only", action="store_true", help="Prepare offline inputs without invoking Docker")
    value.add_argument("--reuse-wheelhouse", type=Path, help="Reuse previously verified dependency wheels")
    value.add_argument("--torch-version", default="2.14.1+cpu", help="Explicit CPU Torch version")
    return value


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 << 20), b""):
            value.update(block)
    return value.hexdigest()


def wheel_metadata(path):
    with zipfile.ZipFile(path) as archive:
        entries = [name for name in archive.namelist()
                   if name.count("/") == 1 and name.endswith(".dist-info/METADATA")]
        if len(entries) != 1:
            raise ValueError("Wheel must contain exactly one distribution metadata document")
        metadata = BytesParser().parsebytes(archive.read(entries[0]))
    name, version = metadata["Name"], metadata["Version"]
    if not name or not version:
        raise ValueError("Wheel name/version metadata missing")
    return re.sub(r"[-_.]+", "-", name).lower(), version


def main(argv=None):
    args = parser().parse_args(argv)
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", args.base_image):
        raise ValueError("Base image must be an exact operator-verified image ID")
    parent = args.output_dir.resolve()
    if parent == ROOT or parent.is_relative_to(ROOT):
        raise ValueError("Keep validation images and wheel artifacts outside the checkout")
    if args.docker_host and not args.docker_host.startswith("unix:///"):
        raise ValueError("Use an explicitly selected private local Docker socket")
    if not args.stage_only and not args.docker_host:
        raise ValueError("Offline image build requires the task-owned Docker socket")
    stage = parent / ("build-" + uuid.uuid4().hex[:8])
    wheelhouse, logs = stage / "wheelhouse", stage / "logs"
    wheelhouse.mkdir(parents=True)
    logs.mkdir()
    state = {"status": "staging", "stage": str(stage), "base_image": args.base_image,
             "torch_version": args.torch_version, "steps": [], "wheels": []}
    env = dict(os.environ, PYTHONUNBUFFERED="1", OMP_NUM_THREADS="2", MKL_NUM_THREADS="2",
               OPENBLAS_NUM_THREADS="2", DOCKER_BUILDKIT="0")

    def save():
        (stage / "manifest.json").write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
        (parent / "latest-build.txt").write_text(str(stage) + "\n")

    def run(label, command, *, environment=env):
        path = logs / (label + ".log")
        start = time.monotonic()
        with path.open("w") as stream:
            result = subprocess.run([str(item) for item in command], cwd=ROOT, env=environment,
                                    stdout=stream, stderr=subprocess.STDOUT)
        step = {"name": label, "returncode": result.returncode, "seconds": round(time.monotonic()-start, 3),
                "log": str(path)}
        state["steps"].append(step)
        save()
        print(json.dumps(step), flush=True)
        if result.returncode:
            raise RuntimeError(f"{label} failed; see {path}")
        return path

    try:
        host_env = stage / "host-env"
        run("host-env", [args.uv, "venv", "--seed", "--python", args.python, host_env])
        python = host_env / "bin/python"
        host_version = run("host-python", [python, "-c", "import sys; assert sys.version_info[:2]==(3,14); print(sys.version)"])
        state["host_python"] = host_version.read_text().strip()
        run("build-tools", [python, "-m", "pip", "install", "build==" + BUILD_INPUTS["build"]])
        project = stage / "project-wheels"
        project.mkdir()
        for name, path in (("hf2l", ROOT), ("exchange", ROOT / "packages/exchange"), ("jobs", ROOT / "packages/jobs")):
            run("wheel-" + name, [python, "-m", "build", "--wheel", "--outdir", project, path])
        if args.reuse_wheelhouse:
            previous = args.reuse_wheelhouse.resolve()
            records = json.loads((previous / "wheel-manifest.json").read_text())
            expected = {item["filename"]: item for item in records}
            actual = {path.name: path for path in previous.glob("*.whl")}
            if set(actual) != set(expected):
                raise ValueError("Reused wheel inputs differ from the verified manifest")
            for filename, path in actual.items():
                name, version = wheel_metadata(path)
                record = expected[filename]
                if (digest(path) != record["sha256"] or name != record["name"] or version != record["version"]):
                    raise ValueError("Reused wheel input failed identity or SHA256 verification")
                if name not in {"hf2l", "hf2l-exchange", "hf2l-jobs"}:
                    shutil.copy2(path, wheelhouse / path.name)
            state["reused_wheelhouse"] = str(previous)
        available = {wheel_metadata(path)[0]: wheel_metadata(path)[1] for path in wheelhouse.glob("*.whl")}
        missing = []
        for name, version in BUILD_INPUTS.items():
            if name in available and available[name] != version:
                raise ValueError("Previously approved build frontend differs; explicitly prepare new inputs")
            if name not in available:
                missing.append(f"{name}=={version}")
        if missing:
            run("build-frontends", [python, "-m", "pip", "download", "--only-binary=:all:", "--no-deps",
                                   "--dest", wheelhouse, *missing])
        state["build_frontend"] = BUILD_INPUTS
        projects = {wheel_metadata(path)[0]: path for path in project.glob("*.whl")}
        if set(projects) != {"hf2l", "hf2l-exchange", "hf2l-jobs"}:
            raise ValueError("Expected exactly the three trusted project distributions")
        state["worker_sources"] = {}
        for distribution, member, source in (
            ("hf2l", "hf2l/client_steps.py", ROOT / "hf2l/client_steps.py"),
            ("hf2l-jobs", "hf2l_jobs/runtime.py", ROOT / "packages/jobs/src/hf2l_jobs/runtime.py"),
            ("hf2l-jobs", "hf2l_jobs/workflow.py", ROOT / "packages/jobs/src/hf2l_jobs/workflow.py"),
            ("hf2l-jobs", "hf2l_jobs/build.py", ROOT / "packages/jobs/src/hf2l_jobs/build.py"),
        ):
            with zipfile.ZipFile(projects[distribution]) as archive:
                content = archive.read(member)
            if content != source.read_bytes():
                raise ValueError("Frozen worker source changed during image staging")
            state["worker_sources"][member] = hashlib.sha256(content).hexdigest()
        torch_wheels = [p for p in wheelhouse.glob("torch-*.whl") if wheel_metadata(p)[1] == args.torch_version]
        if not torch_wheels:
            run("cpu-torch-wheel", [python, "-m", "pip", "download", "--no-deps", "--only-binary=:all:",
                "--dest", wheelhouse, "--index-url", "https://download.pytorch.org/whl/cpu",
                "torch==" + args.torch_version])
            torch_wheels = list(wheelhouse.glob("torch-*.whl"))
        if len(torch_wheels) != 1 or wheel_metadata(torch_wheels[0])[1] != args.torch_version:
            raise ValueError("Exactly one pinned CPU Torch wheel is required")
        platforms = []
        # Debian trixie uses glibc 2.41. Never select wheels requiring a newer libc.
        for minor in range(41, 16, -1):
            platforms.extend(("--platform", f"manylinux_2_{minor}_x86_64"))
        platforms.extend(("--platform", "manylinux2014_x86_64"))
        indexes = ["--no-index"] if args.reuse_wheelhouse else []
        run("runtime-wheelhouse", [python, "-m", "pip", "download", *indexes, "--only-binary=:all:",
            "--python-version", "3.14", "--implementation", "cp", "--abi", "cp314", "--abi", "abi3",
            "--abi", "none", *platforms, "--dest", wheelhouse, "--find-links", project,
            "--find-links", wheelhouse, str(projects["hf2l"]) + "[torch,hf,examples,exchange]",
            str(projects["hf2l-exchange"]), str(projects["hf2l-jobs"]), str(torch_wheels[0]),
            *[f"{name}=={version}" for name, version in BUILD_INPUTS.items()]])
        packages = {}
        for path in sorted(wheelhouse.glob("*.whl")):
            name, version = wheel_metadata(path)
            if name in packages:
                raise ValueError(f"Multiple wheel versions for {name}; use a fresh input directory")
            packages[name] = {"name": name, "version": version, "sha256": digest(path), "filename": path.name}
        state["wheels"] = list(packages.values())
        requirements = "\n".join(f"{name}=={item['version']} --hash=sha256:{item['sha256']}"
                                   for name, item in sorted(packages.items())) + "\n"
        (wheelhouse / "requirements.txt").write_text(requirements)
        (wheelhouse / "wheel-manifest.json").write_text(json.dumps(state["wheels"], indent=2, sort_keys=True) + "\n")
        for directory, names in (("dependencies", set(packages) - set(projects)),
                                 ("projects", set(projects))):
            destination = stage / directory
            destination.mkdir()
            lines = []
            for name in sorted(names):
                item = packages[name]
                shutil.copy2(wheelhouse / item["filename"], destination / item["filename"])
                lines.append(f"{name}=={item['version']} --hash=sha256:{item['sha256']}")
            (destination / "requirements.txt").write_text("\n".join(lines) + "\n")
        shutil.copy2(Path(__file__).with_name("Dockerfile"), stage / "Dockerfile")
        (stage / ".dockerignore").write_text("*\n!Dockerfile\n!dependencies/\n!dependencies/**\n!projects/\n!projects/**\n")
        state["status"] = "staged"
        save()
        if not args.stage_only:
            docker = ["sudo", "-n", "docker", "--host", args.docker_host]
            inspect = run("base-inspect", [*docker, "image", "inspect", "--format", "{{.Id}}", args.base_image])
            if inspect.read_text().strip() != args.base_image:
                raise ValueError("Actual local base image differs from the approved image")
            base_version = run("base-python", [*docker, "run", "--rm", "--runtime=runsc", "--network=none",
                 "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit=64",
                 "--cpus=1", "--memory=256m", "--entrypoint=python", args.base_image,
                 "-c", "import sys; assert sys.version_info[:2]==(3,14); print(sys.version)"])
            state["base_python"] = base_version.read_text().strip()
            tag = "hf2l-jobs-approved-base:" + args.base_image.split(":", 1)[1]
            run("base-tag", [*docker, "tag", args.base_image, tag])
            run("offline-build", [*docker, "build", "--network", "none", "--pull=false", "--build-arg",
                                 "BASE_IMAGE=" + tag, "--iidfile", stage / "image.id", stage])
            state["image_id"] = (stage / "image.id").read_text().strip()
            if not re.fullmatch(r"sha256:[a-f0-9]{64}", state["image_id"]):
                raise ValueError("Docker did not return an immutable image ID")
            state["image_tag"] = "hf2l-jobs-runtime:" + stage.name
            run("image-pin", [*docker, "tag", state["image_id"], state["image_tag"]])
            archive = stage / "worker-image.tar"
            run("image-save", [*docker, "image", "save", "--output", archive, state["image_id"]])
            run("image-archive-owner", ["sudo", "-n", "chown", f"{os.getuid()}:{os.getgid()}", archive])
            state["image_archive"] = {"path": str(archive), "sha256": digest(archive),
                                      "size_bytes": archive.stat().st_size}
            save()
            image_inspect = run("image-inspect", [*docker, "image", "inspect", state["image_id"]])
            state["image_inspect"] = str(image_inspect)
            # Smoke import does not qualify adversarial sandbox isolation or training.
            run("image-help", [*docker, "run", "--rm", "--runtime=runsc", "--network=none",
                 "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit=64",
                 "--cpus=2", "--memory=1g", "--entrypoint=python", state["image_id"],
                 "-m", "hf2l_jobs.runtime", "--help"])
            probe = ("import torch, hf2l, hf2l_jobs, hf2l_exchange; "
                     "from safetensors.torch import save_file, load_file; "
                     "torch.set_num_threads(2); torch.manual_seed(7); "
                     "model=torch.nn.Sequential(torch.nn.Conv2d(1,2,5),torch.nn.ReLU(),"
                     "torch.nn.Flatten(),torch.nn.Linear(1152,10)); "
                     "optimizer=torch.optim.SGD(model.parameters(),lr=0.01); "
                     "loss=torch.nn.functional.cross_entropy(model(torch.randn(2,1,28,28)),torch.tensor([1,2])); "
                     "loss.backward(); optimizer.step(); "
                     "save_file(model.state_dict(),'/tmp/probe.safetensors'); "
                     "assert set(load_file('/tmp/probe.safetensors'))==set(model.state_dict()); "
                     "print({'torch':torch.__version__,'loss':float(loss.detach()),'checkpoint':'verified'})")
            run("image-cpu-training", [*docker, "run", "--rm", "--runtime=runsc", "--network=none",
                 "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit=128",
                 "--cpus=2", "--memory=1g", "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m",
                 "--entrypoint=python", state["image_id"], "-c", probe])
            build_probe = ("from pathlib import Path; import subprocess,sys,zipfile; "
                           "root=Path('/tmp/source');root.mkdir();"
                           "(root/'pyproject.toml').write_text('[build-system]\\nrequires=[\"setuptools\",\"wheel\"]\\nbuild-backend=\"setuptools.build_meta\"\\n[project]\\nname=\"hf2l-build-probe\"\\nversion=\"0.0.0\"\\n');"
                           "(root/'build_probe.py').write_text('VALUE=7\\n');"
                           "subprocess.run([sys.executable,'-m','build','--wheel','--no-isolation','--outdir','/tmp/dist',str(root)],check=True);"
                           "wheel=next(Path('/tmp/dist').glob('*.whl'));"
                           "archive=zipfile.ZipFile(wheel);assert 'build_probe.py' in archive.namelist();"
                           "print({'build':'verified','wheel':wheel.name})")
            run("image-build-frontend", [*docker, "run", "--rm", "--runtime=runsc", "--network=none",
                 "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit=128",
                 "--cpus=2", "--memory=1g", "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m",
                 "--entrypoint=python", state["image_id"], "-c", build_probe])
            state["status"] = "built"
            save()
        print(json.dumps({"manifest": str(stage / "manifest.json"), "status": state["status"],
                          "image_id": state.get("image_id")}), flush=True)
        return 0
    except BaseException as exc:
        state["status"] = "failed"
        state["error"] = f"{type(exc).__name__}: {exc}"
        save()
        raise


if __name__ == "__main__":
    raise SystemExit(main())
