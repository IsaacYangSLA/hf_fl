"""Credential-free offline wheel builds, invoked only inside a qualified sandbox.

Importing this module never executes source hooks or loads training plugins. The
node executor supplies resource/network isolation; this worker supplies immutable
input checks and never resolves or installs dependencies.
"""
from __future__ import annotations

import hashlib
from importlib import metadata
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
from types import MappingProxyType
from typing import Literal, Mapping
import zipfile

from pydantic import Field, StrictInt, field_serializer, field_validator, model_validator

from .domain import FrozenInput, JobSpec, canonical_json, validate_identifier


class BuildSafetyError(RuntimeError):
    """Approved immutable inputs or private output could not be established."""


def _relative(value: str, *, dot=False) -> str:
    if dot and value == ".":
        return value
    if (not value or PurePosixPath(value).is_absolute() or "\\" in value or
            any(part in ("", ".", "..") for part in value.split("/"))):
        raise ValueError("Build paths must be canonical source-relative paths")
    return value


class BuildConfig(FrozenInput):
    schema_version: Literal[1] = 1
    role: Literal["build"] = "build"
    job_id: str
    attempt_id: str
    component_id: str
    epoch: StrictInt = Field(ge=1)
    spec: JobSpec
    spec_digest: str
    source_dir: str = "/job/source"
    state_dir: str = "/job/state"
    source_manifest: Mapping[str, str]
    project_subdir: str = "."
    approved_dependencies: Mapping[str, str]

    @field_validator("job_id", "attempt_id", "component_id")
    @classmethod
    def identifiers(cls, value):
        return validate_identifier(value)

    @field_validator("source_dir", "state_dir")
    @classmethod
    def roots(cls, value):
        if not Path(value).is_absolute() or any(part in (".", "..") for part in value.split("/")):
            raise ValueError("Build roots must be canonical absolute paths")
        if value == "/":
            raise ValueError("Build roots cannot select the filesystem root")
        return value.rstrip("/")

    @field_validator("project_subdir")
    @classmethod
    def project_path(cls, value):
        return _relative(value, dot=True)

    @field_validator("source_manifest")
    @classmethod
    def manifest(cls, value):
        for name, digest in value.items():
            _relative(name)
            if not re.fullmatch(r"[a-f0-9]{64}", digest):
                raise ValueError("Invalid source manifest digest")
        if not value:
            raise ValueError("Builds require an immutable source manifest")
        return MappingProxyType(dict(value))

    @field_validator("approved_dependencies")
    @classmethod
    def dependency_inputs(cls, value):
        approved = {}
        for name, version in value.items():
            if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name) or
                    not version or len(version) > 200 or
                    not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.!+_-]*", version)):
                raise ValueError("Approved dependencies require distribution names and exact versions")
            normalized = re.sub(r"[-_.]+", "-", name).lower()
            if normalized in approved:
                raise ValueError("Duplicate normalized dependency approval")
            approved[normalized] = version
        if "build" not in approved:
            raise ValueError("The fixed build frontend must be explicitly approved")
        return MappingProxyType(approved)

    @field_serializer("source_manifest", "approved_dependencies")
    def mappings(self, value):
        return dict(value)

    @model_validator(mode="after")
    def immutable_binding(self):
        if self.spec.digest != self.spec_digest:
            raise ValueError("Build specification digest differs from its immutable job")
        component = next((item for item in self.spec.components if item.component_id == self.component_id), None)
        if component is None or component.role != "build":
            raise ValueError("Build worker must bind its assigned build component")
        source, state = Path(self.source_dir), Path(self.state_dir)
        if source == state or source in state.parents or state in source.parents:
            raise ValueError("Build source and private state must be separate roots")
        return self

    def to_dict(self):
        return self.model_dump(mode="json")

    @property
    def durable_binding(self):
        return {"schema_version": 1, "job_id": self.job_id,
                "component_id": self.component_id, "spec_digest": self.spec_digest,
                "source_commit": self.spec.source_commit,
                "source_manifest": dict(self.source_manifest),
                "project_subdir": self.project_subdir,
                "approved_dependencies": dict(self.approved_dependencies)}



class BuildArtifact(FrozenInput):
    """Portable descriptor for one opaque, job-private wheel."""
    filename: str
    sha256: str
    size_bytes: StrictInt = Field(gt=0, le=1 << 40)

    @field_validator("filename")
    @classmethod
    def basename(cls, value):
        if (len(value) > 255 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+!-]*\.whl", value)
                or "/" in value or "\\" in value):
            raise ValueError("Build artifacts require a wheel basename")
        return value

    @field_validator("sha256")
    @classmethod
    def digest(cls, value):
        if not re.fullmatch(r"[a-f0-9]{64}", value):
            raise ValueError("Build artifact requires a SHA-256 digest")
        return value

    def to_dict(self):
        return self.model_dump(mode="json")


class BuildBinding(FrozenInput):
    """Immutable job/source/dependency identity attached to an untrusted result."""
    schema_version: Literal[1] = 1
    job_id: str
    component_id: str
    spec_digest: str
    source_commit: str
    source_manifest: Mapping[str, str]
    project_subdir: str
    approved_dependencies: Mapping[str, str]

    @field_validator("job_id", "component_id")
    @classmethod
    def identifiers(cls, value):
        return validate_identifier(value)

    @field_validator("spec_digest")
    @classmethod
    def spec_hash(cls, value):
        if not re.fullmatch(r"[a-f0-9]{64}", value):
            raise ValueError("Build result requires an immutable specification digest")
        return value

    @field_validator("source_commit")
    @classmethod
    def source_hash(cls, value):
        if not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", value):
            raise ValueError("Build result requires an immutable source commit")
        return value

    @field_validator("source_manifest")
    @classmethod
    def manifest(cls, value):
        return BuildConfig.manifest(value)

    @field_validator("project_subdir")
    @classmethod
    def project_path(cls, value):
        return _relative(value, dot=True)

    @field_validator("approved_dependencies")
    @classmethod
    def dependencies(cls, value):
        return BuildConfig.dependency_inputs(value)

    @field_serializer("source_manifest", "approved_dependencies")
    def mappings(self, value):
        return dict(value)

    def to_dict(self):
        return self.model_dump(mode="json")


class BuildResult(FrozenInput):
    """Bounded JSON declaration; collectors independently verify opaque bytes."""
    schema_version: Literal[1] = 1
    status: Literal["completed"]
    binding: BuildBinding
    wheel: BuildArtifact

    def validate_binding(self, config: BuildConfig):
        if self.binding.to_dict() != config.durable_binding:
            raise BuildSafetyError("Build result belongs to different immutable job inputs")
        return self

    def to_dict(self):
        return self.model_dump(mode="json")


def _safe(path: Path) -> Path:
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            raise BuildSafetyError("Build paths cannot contain symlinks")
    return path


def _source_manifest(root: Path):
    _safe(root)
    if not root.is_dir():
        raise BuildSafetyError("The immutable build source is missing")
    result = {}
    for path in sorted(root.rglob("*")):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise BuildSafetyError("Build source contains a link or special file")
        result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def _write(path: Path, value):
    _safe(path)
    temporary = path.with_name(path.name + ".tmp")
    _safe(temporary)
    with temporary.open("w", encoding="utf-8") as stream:
        os.chmod(temporary, 0o600)
        stream.write(canonical_json(value) + "\n")
    temporary.replace(path)


def _read(path: Path):
    _safe(path)
    return json.loads(path.read_text(encoding="utf-8"))


def _environment(state: Path):
    home = _safe(state / "home")
    cache = _safe(state / "cache")
    temporary = _safe(state / "tmp")
    for path in (home, cache, temporary):
        path.mkdir(mode=0o700, exist_ok=True)
    # A fresh allowlist prevents inherited Git, provider, pip-index, user Python,
    # proxy, LD_PRELOAD, credential-helper or manager settings entering hooks.
    return {"PATH": str(Path(sys.executable).parent) + ":/usr/local/bin:/usr/bin:/bin",
            "HOME": str(home), "TMPDIR": str(temporary),
            "XDG_CACHE_HOME": str(cache), "LANG": "C.UTF-8",
            "PIP_CONFIG_FILE": os.devnull, "PIP_NO_INDEX": "1",
            "PIP_NO_INPUT": "1", "PIP_NO_CACHE_DIR": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1", "UV_OFFLINE": "true",
            "UV_NO_CACHE": "true", "PYTHONNOUSERSITE": "1"}


def _dependencies(config):
    for name, expected in config.approved_dependencies.items():
        try:
            actual = metadata.version(name)
        except metadata.PackageNotFoundError as exc:
            raise BuildSafetyError("An approved build dependency is absent: " + name) from exc
        if actual != expected:
            raise BuildSafetyError("An approved build dependency version differs: " + name)


def _requirements(requirements, config):
    # Import only during sandbox execution. The control plane can validate
    # BuildConfig without importing a build frontend or executing a backend.
    from packaging.requirements import InvalidRequirement, Requirement
    from packaging.utils import canonicalize_name
    for value in requirements:
        try:
            requirement = Requirement(value)
        except InvalidRequirement as exc:
            raise BuildSafetyError("Build dependency must be an approved installed distribution") from exc
        if requirement.url is not None:
            raise BuildSafetyError("URL and VCS build dependencies are forbidden")
        if requirement.marker is not None and not requirement.marker.evaluate():
            continue
        name = canonicalize_name(requirement.name)
        expected = config.approved_dependencies.get(name)
        if expected is None or not requirement.specifier.contains(expected, prereleases=True):
            raise BuildSafetyError("Build requires an unapproved dependency: " + name)
        if requirement.extras:
            # Extra dependency resolution would require separately approved
            # closure metadata; v1 deliberately requires the explicit inputs.
            raise BuildSafetyError("Dependency extras are unsupported by the offline build approval")


def _wheel(path: Path):
    _safe(path)
    if not path.is_file() or path.suffix != ".whl":
        raise BuildSafetyError("Build backend did not produce a private wheel")
    from packaging.utils import parse_wheel_filename
    try:
        parse_wheel_filename(path.name)
        with zipfile.ZipFile(path) as archive:
            for entry in archive.infolist():
                name = entry.filename.rstrip("/")
                _relative(name)
                mode = entry.external_attr >> 16
                if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)):
                    raise BuildSafetyError("Build wheel contains a link or special file")
    except (ValueError, zipfile.BadZipFile) as exc:
        raise BuildSafetyError("Build backend produced an invalid wheel") from exc
    return {"filename": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size_bytes": path.stat().st_size}


def run_worker(config: BuildConfig) -> int:
    """Execute one fixed wheel build inside the node's qualified sandbox.

    The source never enters sys.path in this process. Build backend hooks execute
    in subprocesses with a private allowlisted environment. The executor remains
    responsible for deadline, PID/CPU/RAM/I/O/disk and network enforcement.
    """
    if not isinstance(config, BuildConfig):
        config = BuildConfig.model_validate(config)
    source, state = _safe(Path(config.source_dir)), _safe(Path(config.state_dir))
    if _source_manifest(source) != dict(config.source_manifest):
        raise BuildSafetyError("Build source differs from its immutable manifest")
    _dependencies(config)
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    binding_path = state / ".build-binding.json"
    if binding_path.exists():
        if _read(binding_path) != config.durable_binding:
            raise BuildSafetyError("Private build state belongs to different immutable inputs")
    else:
        for existing in state.iterdir():
            if (existing.name not in {"cache", "logs", "artifacts"} or
                    existing.is_symlink() or not existing.is_dir() or any(existing.iterdir())):
                raise BuildSafetyError("Unbound nonempty private build state cannot be adopted")
        _write(binding_path, config.durable_binding)
    artifacts = _safe(state / "artifacts")
    artifacts.mkdir(mode=0o700, exist_ok=True)
    result_path = artifacts / "build.json"
    if result_path.exists():
        try:
            result = BuildResult.model_validate(_read(result_path)).validate_binding(config).to_dict()
        except ValueError as exc:
            raise BuildSafetyError("Retained build result has an invalid descriptor") from exc
        filename = result["wheel"]["filename"]
        if not isinstance(filename, str) or "/" in filename or "\\" in filename:
            raise BuildSafetyError("Retained wheel must be a private artifact basename")
        _relative(filename)
        wheel = _safe(artifacts / filename)
        if _wheel(wheel) != result["wheel"]:
            raise BuildSafetyError("Retained private wheel differs from its build result")
        return 0
    progress = state / "progress.json"
    work = _safe(state / "build")
    if work.exists():
        if not work.is_dir():
            raise BuildSafetyError("Private build work directory is unsafe")
        shutil.rmtree(work)
    work.mkdir(mode=0o700)
    copied = work / "source"
    shutil.copytree(source, copied)
    # Source snapshots may carry read-only modes. The sandbox's copy is private.
    for path in (copied, *copied.rglob("*")):
        path.chmod(0o700 if path.is_dir() or path.stat().st_mode & 0o111 else 0o600)
    if _source_manifest(copied) != dict(config.source_manifest):
        raise BuildSafetyError("Private source copy differs from the immutable snapshot")
    project = _safe(copied / config.project_subdir)
    if not project.is_dir() or not (project / "pyproject.toml").is_file():
        raise BuildSafetyError("Approved build project has no pyproject.toml")
    output = work / "wheel"
    output.mkdir(mode=0o700)
    environment = _environment(state)
    _write(progress, {"phase": "building", "job_id": config.job_id, "epoch": config.epoch})
    try:
        import build

        def backend_runner(command, cwd=None, extra_environ=None):
            directory = _safe(Path(cwd)) if cwd else project
            if directory != copied and copied not in directory.parents:
                raise BuildSafetyError("Backend work escaped its private source copy")
            extra = dict(extra_environ or {})
            if any(not name.startswith("_PYPROJECT_HOOKS_") for name in extra):
                raise BuildSafetyError("Build frontend requested an unapproved hook environment")
            subprocess.run(command, cwd=directory, env={**environment, **extra},
                           stdout=sys.stderr, stderr=sys.stderr, check=True)

        builder = build.ProjectBuilder(str(project), python_executable=sys.executable,
                                       runner=backend_runner)
        _requirements(builder.build_system_requires, config)
        _requirements(builder.get_requires_for_build("wheel"), config)
        built = Path(builder.build("wheel", str(output)))
        if built.parent != output or len(list(output.iterdir())) != 1:
            raise BuildSafetyError("Backend outputs must be one private wheel")
        wheel = _wheel(built)
        target = _safe(artifacts / wheel["filename"])
        if target.exists():
            raise BuildSafetyError("An untracked private artifact already exists")
        built.replace(target)
        target.chmod(0o400)
        result = BuildResult(schema_version=1, status="completed",
                             binding=config.durable_binding, wheel=wheel).to_dict()
        _write(result_path, result)
        _write(progress, {"phase": "completed", "job_id": config.job_id, "epoch": config.epoch})
        return 0
    except Exception:
        _write(progress, {"phase": "failed", "job_id": config.job_id,
                          "epoch": config.epoch, "error_code": "offline_build_failed"})
        raise
