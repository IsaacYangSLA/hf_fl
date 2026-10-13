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
BUILD_FRONTEND = {
    "build": "1.6.1", "packaging": "26.3", "pip": "26.2.1",
    "pyproject-hooks": "1.3.3", "setuptools": "84.0.0",
    "setuptools-scm": "9.2.2", "wheel": "0.48.0",
}
PROJECT_NAMES = {"hf2l", "hf2l-exchange", "hf2l-jobs"}
ROOT = Path(__file__).resolve().parents[3]


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--output-dir", type=Path, required=True, help="Task-owned artifact parent outside the checkout")
    value.add_argument("--python", default="/usr/bin/python3.14", help="Trusted host CPython 3.14 interpreter")
    value.add_argument("--uv", default=str(Path.home() / ".local/bin/uv"), help="Trusted deployment UV executable")
    value.add_argument("--base-image", required=True, help="Operator-verified immutable local image ID")
    value.add_argument("--docker-host", help="Private task-owned Docker unix socket")
    value.add_argument("--stage-only", action="store_true", help="Prepare offline inputs without invoking Docker")
    value.add_argument("--reuse-wheelhouse", type=Path, help="Reuse previously verified dependency wheels")
    value.add_argument("--build-wheelhouse", type=Path, help="Approved frontend wheels with sibling build-wheel-manifest.json")
    value.add_argument("--project-wheelhouse", type=Path, help="Reuse the three frozen release wheels without rebuilding")
    value.add_argument("--source-commit", help="Require this full frozen source Git commit")
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
    if (not name or not version or len(metadata.get_all("Name", [])) != 1
            or len(metadata.get_all("Version", [])) != 1):
        raise ValueError("Wheel name/version metadata missing or ambiguous")
    return re.sub(r"[-_.]+", "-", name).lower(), version



def safe_cache_path(path: Path) -> Path:
    """Reject links in every path component before resolving trusted caches."""
    path = Path(os.path.abspath(path))
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError("Wheel cache paths must not contain symlinks")
    if not path.exists():
        raise ValueError("Approved wheel cache is missing")
    return path


def _manifest_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Wheel manifest contains duplicate fields")
        result[key] = value
    return result


def verify_wheel_cache(directory: Path, manifest: Path, identities=None, *,
                       legacy_projects: bool = False):
    """Validate every cache record; only project records may omit both identities."""
    directory, manifest = safe_cache_path(directory), safe_cache_path(manifest)
    if not directory.is_dir() or not manifest.is_file():
        raise ValueError("Wheel cache directory or manifest is invalid")
    recorded = json.loads(manifest.read_text(), object_pairs_hook=_manifest_object)
    records = recorded.get("wheels", []) if isinstance(recorded, dict) else recorded
    if not isinstance(records, list) or not records:
        raise ValueError("Wheel manifest must contain records")
    files, names, verified = set(), set(), []
    for original_record in records:
        if not isinstance(original_record, dict):
            raise ValueError("Invalid wheel manifest record")
        record = dict(original_record)
        filename = record.get("filename", "")
        sha = record.get("sha256", "")
        if (not isinstance(filename, str) or Path(filename).name != filename
                or "/" in filename or "\\" in filename or not filename.endswith(".whl")
                or not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{64}", sha)):
            raise ValueError("Invalid wheel filename or SHA256")
        if filename in files:
            raise ValueError("Duplicate wheel filename or distribution identity")
        path = safe_cache_path(directory / filename)
        if (not path.is_file() or digest(path) != sha
                or ("size_bytes" in record and path.stat().st_size != record["size_bytes"])):
            raise ValueError("Wheel cache failed metadata or SHA256 verification")
        metadata_name, metadata_version = wheel_metadata(path)
        has_name, has_version = "name" in record, "version" in record
        if legacy_projects and not has_name and not has_version:
            name, version = metadata_name, metadata_version
            record.update(name=name, version=version)
        else:
            name, version = record.get("name"), record.get("version")
            if (not has_name or not has_version or not isinstance(name, str)
                    or re.sub(r"[-_.]+", "-", name).lower() != name
                    or not isinstance(version, str) or not version):
                raise ValueError("Invalid or partial wheel identity declaration")
        if (metadata_name, metadata_version) != (name, version):
            raise ValueError("Wheel cache failed metadata or SHA256 verification")
        filename_parts = filename.split("-")
        if (len(filename_parts) < 5
                or re.sub(r"[-_.]+", "-", filename_parts[0]).lower() != name
                or filename_parts[1] != version):
            raise ValueError("Wheel filename differs from its distribution identity")
        if name in names:
            raise ValueError("Duplicate wheel filename or distribution identity")
        files.add(filename)
        names.add(name)
        verified.append(record)
    actual = {path.name for path in directory.glob("*.whl")}
    if actual != files:
        raise ValueError("Wheel cache contains missing or unmanifested wheels")
    if identities is not None and {item["name"]: item["version"] for item in verified} != identities:
        raise ValueError("Approved build frontend versions differ")
    return directory, verified


def verify_project_cache(frozen: Path):
    """Preserve project manifest v1 while verifying exact distribution identities."""
    frozen = safe_cache_path(frozen)
    wheel_paths = list(frozen.glob("*.whl"))
    # Refuse a foreign project set before a missing manifest, as the public API
    # has always done. Metadata is read only after each declared hash verifies.
    filename_names = [re.sub(r"[-_.]+", "-", path.name.split("-")[0]).lower()
                      for path in wheel_paths]
    if len(wheel_paths) != 3 or set(filename_names) != PROJECT_NAMES:
        raise ValueError("Frozen release wheelhouse must contain exactly the three project wheels")
    directory, records = verify_wheel_cache(
        frozen, frozen / "manifest.json", legacy_projects=True)
    if {record["name"] for record in records} != PROJECT_NAMES:
        raise ValueError("Frozen release wheelhouse must contain exactly the three project wheels")
    return directory, records


def reuse_project_wheels(frozen: Path, project: Path) -> None:
    """Verify all frozen project identities and hashes before copying any wheel."""
    frozen, records = verify_project_cache(frozen)
    for record in records:
        shutil.copy2(frozen / record["filename"], project / record["filename"])



def reject_direct_references(directory, records):
    """Keep cached dependency resolution inside the approved wheelhouses."""
    for record in records:
        with zipfile.ZipFile(directory / record["filename"]) as archive:
            entries = [name for name in archive.namelist()
                       if name.count("/") == 1 and name.endswith(".dist-info/METADATA")]
            if len(entries) != 1:
                raise ValueError("Wheel must contain exactly one distribution metadata document")
            metadata = BytesParser().parsebytes(archive.read(entries[0]))
        # PEP 508 direct references contain @ before the optional environment
        # marker. Even file URLs could escape the operator-approved caches.
        if any("@" in requirement.split(";", 1)[0]
               for requirement in metadata.get_all("Requires-Dist", [])):
            raise ValueError("Cached wheels must not contain direct URL dependency references")


def validate_offline_inputs(args):
    """Fail before even Git or UV runs if an approved cache is incomplete."""
    frontend = dependency = project = None
    if args.reuse_wheelhouse and (not args.build_wheelhouse or not args.project_wheelhouse):
        raise ValueError("Cached offline builds require approved frontend and project wheelhouses")
    if args.build_wheelhouse:
        frontend = verify_wheel_cache(args.build_wheelhouse,
                                      args.build_wheelhouse.parent / "build-wheel-manifest.json",
                                      BUILD_FRONTEND)
    if args.project_wheelhouse:
        project = verify_project_cache(args.project_wheelhouse)
    if args.reuse_wheelhouse:
        dependency = verify_wheel_cache(args.reuse_wheelhouse,
                                        args.reuse_wheelhouse / "wheel-manifest.json")
        available = {record["name"]: record["version"] for record in dependency[1]}
        if any(available.get(name) != version for name, version in BUILD_INPUTS.items()):
            raise ValueError("Cached dependency wheelhouse lacks pinned worker build frontends")
        if available.get("torch") != args.torch_version:
            raise ValueError("Cached dependency wheelhouse lacks pinned CPU Torch")
        reject_direct_references(*frontend)
        reject_direct_references(*project)
        reject_direct_references(dependency[0], [
            record for record in dependency[1] if record["name"] not in PROJECT_NAMES])
    return frontend, dependency, project

def main(argv=None):
    args = parser().parse_args(argv)
    frontend_cache, dependency_cache, _ = validate_offline_inputs(args)
    source_commit = None
    if args.source_commit:
        if not re.fullmatch(r"[a-f0-9]{40}", args.source_commit):
            raise ValueError("Source commit must be a full Git identity")
        identity = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, text=True, capture_output=True).stdout.strip()
        changed = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all", "--ignored"], cwd=ROOT, check=True, text=True, capture_output=True).stdout.strip()
        if identity != args.source_commit or changed:
            raise ValueError("Source checkout differs from the frozen release commit")
        source_commit = identity
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
             "torch_version": args.torch_version, "source_commit": source_commit, "steps": [], "wheels": []}
    env = dict(os.environ, PYTHONUNBUFFERED="1", OMP_NUM_THREADS="2", MKL_NUM_THREADS="2",
               OPENBLAS_NUM_THREADS="2", DOCKER_BUILDKIT="0")
    if args.reuse_wheelhouse:
        # --no-index still honors inherited find-links and other resolver
        # overrides. Cached builds accept only the declared local wheelhouses.
        env = {key: value for key, value in env.items()
               if not key.startswith(("PIP_", "UV_"))}
        env.update(PIP_NO_INDEX="1", PIP_CONFIG_FILE=os.devnull,
                   PIP_DISABLE_PIP_VERSION_CHECK="1", UV_OFFLINE="true",
                   UV_NO_CONFIG="true", UV_PYTHON_DOWNLOADS="never")

    def save():
        (stage / "manifest.json").write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
        (parent / "latest-build.txt").write_text(str(stage) + "\n")

    def run(label, command, *, environment=env):
        if args.reuse_wheelhouse:
            words = [str(item) for item in command]
            if ("--seed" in words or "--index-url" in words or "--extra-index-url" in words
                    or ("download" in words and "--no-index" not in words)
                    or (words[0] == str(args.uv) and "--offline" not in words)):
                raise ValueError("Cached build command would permit an online fetch")
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
        if frontend_cache:
            run("host-env", [args.uv, "--no-config", "venv", "--offline",
                             "--no-python-downloads", "--python", args.python, host_env])
        else:
            run("host-env", [args.uv, "venv", "--seed", "--python", args.python, host_env])
        python = host_env / "bin/python"
        host_version = run("host-python", [python, "-c", "import sys; assert sys.version_info[:2]==(3,14); print(sys.version)"])
        state["host_python"] = host_version.read_text().strip()
        if frontend_cache:
            directory, records = frontend_cache
            run("build-tools", [args.uv, "--no-config", "pip", "install", "--python", python,
                                "--offline", "--no-python-downloads", "--no-index", "--no-deps",
                                "--no-cache", "--link-mode", "copy",
                                *[directory / record["filename"] for record in records]])
            state["host_build_frontend"] = records
            state["build_wheelhouse"] = str(directory)
        else:
            run("build-tools", [python, "-m", "pip", "install", "build==" + BUILD_INPUTS["build"]])
        project = stage / "project-wheels"
        project.mkdir()
        if args.project_wheelhouse:
            frozen = args.project_wheelhouse.resolve(strict=True)
            reuse_project_wheels(frozen, project)
            state["project_wheelhouse"] = str(frozen)
        else:
            for name, path in (("hf2l", ROOT), ("exchange", ROOT / "packages/exchange"), ("jobs", ROOT / "packages/jobs")):
                run("wheel-" + name, [python, "-m", "build", "--wheel", "--outdir", project, path])
        if dependency_cache:
            previous, records = dependency_cache
            for record in records:
                if record["name"] not in PROJECT_NAMES:
                    shutil.copy2(previous / record["filename"], wheelhouse / record["filename"])
            state["reused_wheelhouse"] = str(previous)
            state["reused_wheels"] = records
        elif frontend_cache:
            directory, records = frontend_cache
            for record in records:
                if record["name"] in BUILD_INPUTS:
                    shutil.copy2(directory / record["filename"], wheelhouse / record["filename"])
        available = {wheel_metadata(path)[0]: wheel_metadata(path)[1] for path in wheelhouse.glob("*.whl")}
        missing = []
        for name, version in BUILD_INPUTS.items():
            if name in available and available[name] != version:
                raise ValueError("Previously approved build frontend differs; explicitly prepare new inputs")
            if name not in available:
                missing.append(f"{name}=={version}")
        if missing:
            if args.reuse_wheelhouse:
                raise ValueError("Cached wheelhouse has no approved build frontend; online fallback prohibited")
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
            if args.reuse_wheelhouse:
                raise ValueError("Cached wheelhouse has no approved CPU Torch; online fallback prohibited")
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
            # Docker 29 creates --iidfile as root-owned 0600 when invoked with
            # sudo; retain private permissions while returning this owned receipt.
            run("image-id-owner", ["sudo", "-n", "chown", f"{os.getuid()}:{os.getgid()}", stage / "image.id"])
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
