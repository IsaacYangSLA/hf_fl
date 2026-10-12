"""Approved immutable Git trees; fetching never executes repository content."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
import stat
import subprocess
import tempfile
import selectors
import shutil
import signal
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Callable, Iterable, Mapping
from urllib.parse import urlsplit

from .domain import JobSpec, validate_identifier


class SourceError(ValueError):
    """A source cannot safely be materialized under its approved policy."""


@dataclass(frozen=True)
class SourceApproval:
    source_id: str
    projects: frozenset[str]
    url: str | None = None
    mirror_path: Path | None = None
    commits: frozenset[str] = field(default_factory=frozenset)
    max_bytes: int = 256 * 1024**2
    max_files: int = 100_000
    max_git_bytes: int = 256 * 1024**2
    max_git_files: int = 100_000

    def __post_init__(self):
        validate_identifier(self.source_id)
        if (self.url is None) == (self.mirror_path is None):
            raise SourceError("Approve exactly one HTTPS URL or trusted local mirror")
        if not self.projects or not self.commits or self.max_bytes <= 0 or self.max_files <= 0:
            raise SourceError("Approval requires projects, pinned commits and positive limits")
        for name, maximum in (("max_bytes", 1024**3), ("max_files", 100_000), ("max_git_bytes", 1024**3), ("max_git_files", 100_000)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise SourceError("Source approval resource bounds exceed the supported limits")
        for project in self.projects:
            validate_identifier(project)
        if any(not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", item) for item in self.commits):
            raise SourceError("Approved commits must be exact lowercase object identifiers")
        if self.mirror_path is not None:
            path = Path(self.mirror_path)
            if not path.is_absolute() or path.is_symlink() or not path.is_dir():
                raise SourceError("Trusted mirror must be an existing absolute directory")
            object.__setattr__(self, "mirror_path", path.resolve())


@dataclass(frozen=True)
class SourceSnapshot:
    source_id: str
    commit: str
    path: Path
    manifest: Mapping[str, str]
    digest: str
    bytes: int
    physical_bytes: int | None = None


def metadata_peak_bytes(approval: SourceApproval) -> int:
    """Conservative file rounding and bounded directory-entry storage."""
    return 8192 * (3 * approval.max_files + 1024)


def git_peak_bytes(approval: SourceApproval) -> int:
    """Object reception and its bounded file/directory metadata storage."""
    return approval.max_git_bytes + 8192 * (3 * approval.max_git_files + 1024)


def source_physical_bytes(path: Path | str, approval: SourceApproval) -> int:
    """Measure owned snapshot blocks without following any link or mount."""
    from .collection import CollectionError, SafeCollector
    try:
        with SafeCollector(path, max_files=approval.max_files,
                           max_entries=3 * approval.max_files + 1024,
                           max_file_bytes=approval.max_bytes, max_total_bytes=approval.max_bytes) as reader:
            root = os.fstat(reader._root_fd)
            if root.st_uid != os.geteuid():
                raise SourceError("Source physical inventory changed ownership")
            count, files, logical_bytes = 0, 0, 0
            def measure(descriptor, depth):
                nonlocal count, files, logical_bytes
                info = os.fstat(descriptor)
                total = info.st_blocks * 512
                with os.scandir(descriptor) as entries:
                    for entry in entries:
                        count += 1
                        if count > 3 * approval.max_files + 1024 or depth >= 32:
                            raise SourceError("Source physical inventory exceeds entry/depth bound")
                        before = os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)
                        if before.st_dev != root.st_dev or before.st_uid != os.geteuid():
                            raise SourceError("Source physical inventory crosses ownership or filesystem")
                        if stat.S_ISDIR(before.st_mode):
                            child = reader._directory(entry.name, descriptor)
                            try:
                                current = os.fstat(child)
                                if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
                                    raise SourceError("Source directory changed during physical inventory")
                                total += measure(child, depth + 1)
                            finally:
                                os.close(child)
                        else:
                            reader._validate_file(before)
                            files += 1
                            logical_bytes += before.st_size
                            if before.st_size > approval.max_bytes or logical_bytes > approval.max_bytes:
                                raise SourceError("Source physical inventory exceeds logical byte bound")
                            if files > approval.max_files:
                                raise SourceError("Source physical inventory exceeds file bound")
                            total += before.st_blocks * 512
                return total
            return measure(reader._root_fd, 0)
    except (CollectionError, OSError) as error:
        raise SourceError("Source physical inventory contains unsafe or inaccessible paths") from error


class SourceRegistry:
    def __init__(self, approvals: Iterable[SourceApproval] = (), *, allowed_hosts: Iterable[str] = (), resolver: Callable = socket.getaddrinfo):
        values = tuple(approvals)
        self.approvals = {item.source_id: item for item in values}
        if len(self.approvals) != len(values):
            raise SourceError("Duplicate source approval")
        self.allowed_hosts = frozenset(host.lower() for host in allowed_hosts)
        self.resolver = resolver

    def authorize(self, project_id: str, source_id: str, commit: str) -> SourceApproval:
        source = self.approvals.get(source_id)
        if source is None or project_id not in source.projects or commit not in source.commits:
            raise SourceError("Source or exact commit is not approved for this project")
        return source

    def _remote(self, source: SourceApproval) -> tuple[str, str]:
        parsed = urlsplit(source.url or "")
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.port not in (None, 443)
                or parsed.hostname.lower() not in self.allowed_hosts
                or not parsed.path.startswith("/") or any(c in (source.url or "") for c in "\r\n\x00")):
            raise SourceError("Source URL must be a fixed approved HTTPS repository without credentials")
        host = parsed.hostname.lower()
        try:
            addresses = sorted({row[4][0] for row in self.resolver(host, 443, type=socket.SOCK_STREAM)})
        except OSError as exc:
            raise SourceError("Approved source host did not resolve") from exc
        if not addresses or any(not ipaddress.ip_address(value).is_global for value in addresses):
            raise SourceError("Source address is not public; private and metadata destinations are forbidden")
        resolved = ",".join("[" + value + "]" if ":" in value else value for value in addresses)
        return source.url, f"{host}:443:{resolved}"

    @staticmethod
    def _bounded_process(command, environment, *, stdout_limit=1024 * 1024,
                         stderr_limit=1024 * 1024, timeout=120,
                         stdout_sink: Callable[[bytes], None] | None = None) -> bytes:
        """Bound subprocess output before buffering it, and kill the whole group."""
        if any(type(value) is not int or value < 1
               for value in (stdout_limit, stderr_limit)):
            raise SourceError("Git output limits must be positive integers")
        if stdout_sink is not None and not callable(stdout_sink):
            raise SourceError("Git stdout sink must be a trusted callable")
        process = None
        selector = selectors.DefaultSelector()
        output = bytearray()
        stdout_bytes = 0
        error_bytes = 0
        completed = False
        deadline = time.monotonic() + timeout
        try:
            process = subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True)
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SourceError("Approved Git source operation exceeded its time limit")
                for key, _ in selector.select(min(1, remaining)):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == "stdout":
                        if stdout_bytes + len(data) > stdout_limit:
                            raise SourceError("Approved Git output exceeds its byte limit")
                        stdout_bytes += len(data)
                        if stdout_sink is None:
                            output.extend(data)
                        else:
                            stdout_sink(data)
                    else:
                        error_bytes += len(data)
                        if error_bytes > stderr_limit:
                            raise SourceError("Approved Git diagnostics exceed their byte limit")
            remaining = max(0.001, deadline - time.monotonic())
            if process.wait(timeout=remaining):
                raise SourceError("Approved Git source operation failed")
            completed = True
            return bytes(output)
        except (OSError, subprocess.SubprocessError) as error:
            raise SourceError("Approved Git source operation failed") from error
        finally:
            selector.close()
            if process is not None:
                # A transport descendant may still own the pipes after the Git
                # leader exited. Failure must fence the whole group regardless
                # of the leader's exit status.
                if not completed:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if process.poll() is None:
                    process.wait(timeout=5)
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()

    @staticmethod
    def _git(repository: Path, *args: str, resolve: str | None = None,
             stdout_limit: int = 1024 * 1024,
             file_limit: int = 256 * 1024**2,
             stdout_sink: Callable[[bytes], None] | None = None) -> bytes:
        limiter = shutil.which("prlimit")
        if not limiter or os.name != "posix" or not Path("/proc/self").is_dir():
            raise SourceError("Bounded Git execution requires Linux prlimit")
        # The trusted Git implementation retains received packs. It never unpacks
        # arbitrary numbers of loose objects into an unbounded host directory.
        command = [limiter, "--as=536870912", "--cpu=120", "--fsize=" + str(file_limit),
                   "--", "git", "--no-optional-locks",
                   "-c", "core.hooksPath=/dev/null", "-c", "core.attributesFile=/dev/null",
                   "-c", "credential.helper=", "-c", "credential.interactive=false",
                   "-c", "http.followRedirects=false", "-c", "http.proxy=",
                   "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
                   "-c", "fetch.unpackLimit=1", "-c", "transfer.unpackLimit=1",
                   "-c", "core.deltaBaseCacheLimit=16777216", "-c", "pack.threads=1"]
        if resolve:
            command += ["-c", "http.curloptResolve=" + resolve]
        command += ["--git-dir=" + str(repository), *args]
        environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/nonexistent",
                       "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                       "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
                       "GIT_ATTR_NOSYSTEM": "1", "LC_ALL": "C"}
        return SourceRegistry._bounded_process(command, environment,
                                               stdout_limit=stdout_limit, stdout_sink=stdout_sink)

    @staticmethod
    @contextmanager
    def _fetch_workspace(source: SourceApproval, parent: Path):
        """HTTPS object reception uses an enforced byte/inode filesystem quota.

        Operator-prepared mirrors are copied with explicit aggregate bounds and
        contain no network side effect, so that path does not require mount
        privileges. HTTPS fails closed if the dedicated bounded mount is absent.
        """
        from .collection import CollectionError, SafeCollector
        parent = Path(parent)
        if not parent.is_absolute() or ".." in parent.parts:
            raise SourceError("Source workspace parent must be an owned absolute directory")
        try:
            with SafeCollector(parent) as collector:
                authority = os.fstat(collector._root_fd)
                if authority.st_uid != os.geteuid() or authority.st_mode & 0o077:
                    raise SourceError("Source workspace parent must be private and owned")
                directory = Path(tempfile.mkdtemp(prefix="hf2l-fetch-", dir=parent))
                current = parent.stat()
                if (authority.st_dev, authority.st_ino) != (current.st_dev, current.st_ino):
                    raise SourceError("Source workspace parent changed during allocation")
        except (CollectionError, OSError) as error:
            raise SourceError("Source workspace parent contains unsafe or inaccessible paths") from error
        mounted = False
        try:
            if source.mirror_path is None:
                options = (f"size={source.max_git_bytes},nr_inodes={source.max_git_files + 1024},"
                           f"mode=0700,uid={os.getuid()},gid={os.getgid()},nodev,nosuid,noexec")
                try:
                    subprocess.run(["sudo", "-n", "mount", "-t", "tmpfs", "-o",
                                    options, "tmpfs", str(directory)], check=True,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=15)
                except (OSError, subprocess.SubprocessError) as error:
                    raise SourceError("HTTPS source fetching requires an enforced private workspace quota") from error
                mounted = True
                information = os.statvfs(directory)
                if information.f_blocks * information.f_frsize > source.max_git_bytes + 4096:
                    raise SourceError("Source workspace quota differs from the approved bound")
            yield directory
        finally:
            if mounted:
                try:
                    subprocess.run(["sudo", "-n", "umount", str(directory)], check=True,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=15)
                except (OSError, subprocess.SubprocessError) as error:
                    # Retain the owned mount; never recursively delete through an
                    # unknown mount or report its resources as released.
                    raise SourceError("Source workspace deletion is unconfirmed") from error
                os.rmdir(directory)
            else:
                shutil.rmtree(directory)

    @staticmethod
    def _copy_mirror_objects(source: SourceApproval, repository: Path) -> None:
        objects = source.mirror_path / "objects"
        if not objects.is_dir():
            objects = source.mirror_path / ".git" / "objects"
        if not objects.is_dir():
            raise SourceError("Approved mirror has no safe object store")
        # Pin every ancestor and each leaf with O_NOFOLLOW. Never rglob an
        # unbounded repository or follow source-controlled object-store links.
        from .collection import CollectionError, SafeCollector
        try:
            with SafeCollector(objects, max_files=source.max_git_files,
                               max_entries=source.max_git_files * 3 + 1024,
                               max_file_bytes=source.max_git_bytes,
                               max_total_bytes=source.max_git_bytes) as collector:
                manifest = collector.list_files()
                total = 0
                for item in manifest:
                    parts = PurePosixPath(item.path).parts
                    if parts[0] == "info":
                        continue
                    data = collector.read(item.path, max_bytes=source.max_git_bytes - total)
                    if len(data) != item.size_bytes or hashlib.sha256(data).hexdigest() != item.sha256:
                        raise SourceError("Mirror objects changed during the bounded copy")
                    total += len(data)
                    target = repository / "objects" / item.path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open("xb") as output:
                        output.write(data)
        except CollectionError as error:
            raise SourceError("Approved mirror object bytes/files exceed bounds or contain unsafe links") from error

    @staticmethod
    def _safe_name(raw: bytes) -> str:
        try:
            name = raw.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise SourceError("Source paths must use UTF-8") from exc
        parts = tuple(name.split("/"))
        forbidden = {".git", ".gitconfig", ".git-credentials", ".netrc", ".ssh"}
        if (not name or name.startswith("/") or "\\" in name or any(ord(c) < 32 or ord(c) == 127 for c in name)
                or any(part in ("", ".", "..") or part.lower() in forbidden for part in parts)
                or len(parts) > 32 or len(raw) > 4096
                or any(len(part.encode("utf-8")) > 255 for part in parts)):
            raise SourceError("Unsafe, too deep or credential-bearing source path")
        return name

    def _verified_git_object(self, repository: Path, kind: str, object_id: str,
                             *, maximum: int) -> bytes:
        """An approved object filename alone is not proof of immutable bytes."""
        content = self._git(repository, "cat-file", kind, object_id, stdout_limit=maximum)
        digest = hashlib.sha1() if len(object_id) == 40 else hashlib.sha256()
        digest.update(kind.encode("ascii") + b" " + str(len(content)).encode("ascii") + b"\0")
        digest.update(content)
        if digest.hexdigest() != object_id:
            raise SourceError("Source immutable Git object digest changed")
        return content

    def materialize(self, project_id: str, source_id: str, commit: str,
                    destination: Path | str, *,
                    workspace_parent: Path | str | None = None) -> SourceSnapshot:
        source = self.authorize(project_id, source_id, commit)
        destination = Path(destination)
        if not destination.is_absolute() or destination.exists() or destination.is_symlink():
            raise SourceError("Snapshot destination must be a new absolute path")
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Object reception and tree output have separate explicit aggregate bounds.
        # No Git directory, history, template or source credentials reach staging.
        fetch_parent = destination.parent if workspace_parent is None else Path(workspace_parent)
        with self._fetch_workspace(source, fetch_parent) as fetch_root:
            repository = fetch_root / "repository.git"
            object_format = "sha1" if len(commit) == 40 else "sha256"
            self._git(repository, "init", "--bare", "--object-format=" + object_format,
                      file_limit=source.max_git_bytes)
            if source.mirror_path is not None:
                self._copy_mirror_objects(source, repository)
            else:
                url, resolved = self._remote(source)
                self._git(repository, "fetch", "--no-tags", "--no-recurse-submodules",
                          "--depth=1", "--", url, commit, resolve=resolved,
                          file_limit=source.max_git_bytes)
            actual = self._git(repository, "rev-parse", "--verify", commit + "^{commit}").decode().strip()
            if actual != commit:
                raise SourceError("Resolved source commit does not match approved object")
            commit_bytes = self._verified_git_object(repository, "commit", commit, maximum=1024**2)
            root_line = commit_bytes.split(b"\n", 1)[0]
            if not re.fullmatch(rb"tree ([a-f0-9]{40}|[a-f0-9]{64})", root_line):
                raise SourceError("Approved Git commit has no immutable root tree")
            root_tree = root_line[5:].decode("ascii")
            self._verified_git_object(repository, "tree", root_tree, maximum=16 * 1024**2)
            verified_trees = {root_tree}
            tree = self._git(repository, "ls-tree", "-rtz", "--full-tree", commit,
                             stdout_limit=min(16 * 1024**2, (3 * source.max_files + 1024) * 4200))
            # Validate the entire immutable tree before creating any of its
            # directories. A file limit alone does not bound ancestor fan-out.
            records, tree_objects, tree_entries, filenames = [], set(), set(), set()
            for entry in tree.split(bytes([0])):
                if not entry:
                    continue
                metadata, raw_name = entry.split(bytes([9]), 1)
                mode, kind, object_id = metadata.decode("ascii").split(" ")
                name = self._safe_name(raw_name)
                is_tree = mode == "040000" and kind == "tree"
                if ((not is_tree and (mode not in ("100644", "100755") or kind != "blob"))
                        or name == ".gitmodules"):
                    raise SourceError("Symlinks, submodules and special source files are unsupported")
                parts = name.split("/")
                tree_entries.update("/".join(parts[:index]) for index in range(1, len(parts) + 1))
                if len(tree_entries) > 3 * source.max_files + 1024:
                    raise SourceError("Source tree entries exceed approved limit")
                if is_tree:
                    tree_objects.add(object_id)
                    continue
                if name in filenames or len(records) >= source.max_files:
                    raise SourceError("Source file count exceeds approved limit")
                filenames.add(name)
                records.append((mode, object_id, name))
            for object_id in sorted(tree_objects - verified_trees):
                self._verified_git_object(repository, "tree", object_id, maximum=16 * 1024**2)
            with tempfile.TemporaryDirectory(prefix="hf2l-source-", dir=destination.parent) as temp:
                staging = Path(temp) / "snapshot"
                staging.mkdir(mode=0o700)
                manifest: dict[str, str] = {}
                total = 0
                for mode, object_id, name in records:
                    size = int(self._git(repository, "cat-file", "-s", object_id))
                    if size < 0 or total + size > source.max_bytes:
                        raise SourceError("Source bytes exceed approved limit")
                    # Stream directly to the exclusive staged file. Only one
                    # <=64KiB pipe chunk is buffered, independently of blob size.
                    path = staging / name
                    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    digest = hashlib.sha256()
                    object_digest = (hashlib.sha1() if len(object_id) == 40 else hashlib.sha256())
                    object_digest.update(b"blob " + str(size).encode("ascii") + b"\0")
                    with path.open("xb") as output:
                        def receive(chunk):
                            output.write(chunk)
                            digest.update(chunk)
                            object_digest.update(chunk)
                        self._git(repository, "cat-file", "blob", object_id,
                                  stdout_limit=max(1, size), stdout_sink=receive)
                        if output.tell() != size or object_digest.hexdigest() != object_id:
                            raise SourceError("Source object size or immutable Git digest changed")
                        output.flush()
                        os.fsync(output.fileno())
                    path.chmod(0o555 if mode == "100755" else 0o444)
                    manifest[name] = digest.hexdigest()
                    total += size
                digest = hashlib.sha256(json.dumps(manifest, sort_keys=True,
                                                  separators=(",", ":")).encode()).hexdigest()
                # Linux needs write permission to update '..' during this rename.
                staging.rename(destination)
                for directory, _, _ in os.walk(destination, topdown=False):
                    Path(directory).chmod(0o555)
                physical = source_physical_bytes(destination, source)
                return SourceSnapshot(source_id, commit, destination, manifest, digest, total, physical)



class RegistryCatalog:
    """Trusted admission approvals; job specifications contain identifiers only."""
    def __init__(self, source_registry: SourceRegistry, runtime_images: Mapping[str, str], *, dataset_bindings: Mapping[str, Iterable[str]] | None = None,
                 secret_refs: Iterable[str] = ()):
        self.source_registry = source_registry
        self.runtime_images = dict(runtime_images)
        self.dataset_bindings = {key: frozenset(value) for key, value in (dataset_bindings or {}).items()}
        self.secret_refs = frozenset(secret_refs)
        self.runtime_projects = {}
        self.dataset_projects = {}
        self.secret_projects = {}
        self.database = None
        if any(not re.fullmatch(r"sha256:[a-f0-9]{64}", digest) for digest in self.runtime_images.values()):
            raise SourceError("Runtime approvals must resolve to immutable SHA-256 image digests")

    @classmethod
    def from_database(cls, database):
        from sqlalchemy import select
        from .models import ApprovedSource, RuntimeImage, ParticipantBinding, SecretReference, Project
        with database.transaction(immediate=False) as session:
            projects = frozenset(session.scalars(select(Project.id)))
            approvals, hosts = [], set()
            for row in session.scalars(select(ApprovedSource).where(ApprovedSource.enabled.is_(True), ApprovedSource.status == "approved")):
                approved_projects = frozenset({row.project_id}) if row.project_id else projects
                details = row.details_json or {}
                mirror = details.get("mirror_path")
                approvals.append(SourceApproval(row.id, approved_projects, url=None if mirror else row.url,
                                                mirror_path=Path(mirror) if mirror else None,
                                                commits=frozenset(row.allowed_commits),
                                                max_bytes=details.get("max_bytes", 256 * 1024**2),
                                                max_files=details.get("max_files", 100_000),
                                                max_git_bytes=details.get("max_git_bytes", 256 * 1024**2),
                                                max_git_files=details.get("max_git_files", 100_000)))
                hosts.update(row.allowed_hosts)
            images = list(session.scalars(select(RuntimeImage).where(RuntimeImage.enabled.is_(True), RuntimeImage.approved.is_(True), RuntimeImage.status == "approved")))
            datasets = list(session.scalars(select(ParticipantBinding).where(ParticipantBinding.enabled.is_(True))))
            secrets = list(session.scalars(select(SecretReference).where(SecretReference.enabled.is_(True))))
            registry = cls(SourceRegistry(approvals, allowed_hosts=hosts), {row.id: row.digest for row in images},
                           dataset_bindings={row.id: [row.participant_id] for row in datasets}, secret_refs=[row.id for row in secrets])
            registry.runtime_projects = {row.id: row.project_id for row in images}
            registry.dataset_projects = {row.id: row.project_id for row in datasets}
            registry.secret_projects = {row.id: row.project_id for row in secrets}
            registry.database = database
            return registry

    def refreshed(self):
        return self.from_database(self.database) if self.database is not None else self

    def validate(self, spec: JobSpec) -> str:
        if self.database is not None:
            current = self.refreshed()
            current.database = None
            return current.validate(spec)
        self.source_registry.authorize(spec.project_id, spec.source_id, spec.source_commit)
        digest = self.runtime_images.get(spec.runtime_image)
        if digest is None and spec.runtime_image in self.runtime_images.values():
            digest = spec.runtime_image
        if digest is None:
            raise SourceError("Runtime image is not approved")
        image_ids = [key for key, value in self.runtime_images.items() if value == digest]
        if not any(self.runtime_projects.get(key) in (None, spec.project_id) for key in image_ids):
            raise SourceError("Runtime image is not approved for this project")
        for participant in spec.participants:
            permitted = self.dataset_bindings.get(participant.dataset_binding)
            if (permitted is None or participant.participant_id not in permitted
                    or self.dataset_projects.get(participant.dataset_binding) not in (None, spec.project_id)):
                raise SourceError("Dataset binding is not locally approved for this participant")
        if (not set(spec.secret_refs.values()).issubset(self.secret_refs)
                or any(self.secret_projects.get(key) not in (None, spec.project_id) for key in spec.secret_refs.values())):
            raise SourceError("Secret reference is not approved")
        return digest
