"""Credential-free model storage for a trusted local POSIX filesystem.

An explicit local principal provides attribution, not remote authentication. All
writers must use this adapter and the same filesystem's advisory lock support.
Snapshots are immutable; refs and their generations are replaced atomically while
holding a per-repository process lock. Network filesystems are not supported.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shutil
import tempfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from hf2l.common.fs import checked_file_paths, safe_relative_path
from hf2l.core.ports import (BackendCapabilities, ModelStore, PublicationConsistency,
                              PublicationUncertain, PublishResult, ResolvedReference, RevisionNotFound, SubmissionCandidate)

_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_REVISION = re.compile(r"[a-f0-9]{32}\Z")


def _reference(value):
    if not isinstance(value, str) or not _REFERENCE.fullmatch(value):
        raise ValueError("Local reference names must be 1-128 letters, digits, periods, underscores or hyphens")
    if _REVISION.fullmatch(value):
        raise ValueError("Reference names cannot shadow immutable local revision IDs")
    return value


def _inside(root: Path, name: str) -> Path:
    relative = safe_relative_path(name)
    path = root / relative
    for parent in [root, *path.relative_to(root).parents]:
        candidate = parent if parent == root else root / parent
        if candidate.is_symlink():
            raise ValueError(f"Symlink paths are not supported: {candidate}")
    if path.is_symlink():
        raise ValueError(f"Symlink paths are not supported: {path}")
    return path



class LocalStore(ModelStore):
    name = "local"
    capabilities = BackendCapabilities(PublicationConsistency.ATOMIC, binds_participants=True,
                                       named_submission_revisions=True)

    def __init__(self, root: str | Path, principal: str):
        if not isinstance(principal, str) or not principal.strip() or len(principal) > 256:
            raise ValueError("Local storage requires a nonempty explicit principal of at most 256 characters")
        if any(ord(char) < 32 for char in principal):
            raise ValueError("Local principal contains a control character")
        if os.name != "posix":
            raise ValueError("The local backend currently requires POSIX advisory filesystem locks")
        self.root = Path(root).expanduser().absolute()
        if self.root.is_symlink():
            raise ValueError("Local storage root cannot be a symlink")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.principal = principal.strip()
        self._closed = False

    def close(self):
        self._closed = True

    def _repo(self, repo_id):
        if self._closed:
            raise RuntimeError("LocalStore is closed")
        if not isinstance(repo_id, str) or not repo_id.strip() or len(repo_id) > 1024:
            raise ValueError("Repository ID must be a nonempty string of at most 1024 characters")
        key = hashlib.sha256(repo_id.encode()).hexdigest()
        repo = self.root / key
        if repo.is_symlink():
            raise ValueError("Local repository directory cannot be a symlink")
        repo.mkdir(exist_ok=True, mode=0o700)
        return repo

    @contextmanager
    def _lock(self, repo_id):
        import fcntl
        repo = self._repo(repo_id)
        descriptor = os.open(repo / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                yield repo
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    @staticmethod
    def _read(path, default=None):
        if path.is_symlink():
            raise ValueError("Local metadata cannot be a symlink")
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            if default is not None:
                return default
            raise RevisionNotFound(f"Unknown local snapshot or reference: {path.name}") from None

    @staticmethod
    def _write(path, value):
        descriptor, temporary = tempfile.mkstemp(prefix=".metadata-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(value, output, sort_keys=True)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    @staticmethod
    def _sync_directory(path):
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _refs(self, repo):
        return self._read(repo / "refs.json", {})

    @staticmethod
    def _snapshot_path(repo, revision):
        if not isinstance(revision, str) or not _REVISION.fullmatch(revision):
            raise ValueError("Invalid immutable local revision")
        root = repo / "snapshots"
        if root.is_symlink() or (root / revision).is_symlink():
            raise ValueError("Local snapshot directory cannot be a symlink")
        return root / revision

    def _snapshot(self, repo, folder, paths, **metadata):
        paths = checked_file_paths(folder, paths)
        snapshots = repo / "snapshots"
        if snapshots.is_symlink():
            raise ValueError("Local snapshot directory cannot be a symlink")
        snapshots.mkdir(exist_ok=True, mode=0o700)
        revision = uuid.uuid4().hex
        staged = Path(tempfile.mkdtemp(prefix=".staging-", dir=snapshots))
        try:
            files = staged / "files"
            files.mkdir()
            for name in paths:
                source, destination = _inside(Path(folder), name), files / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                with os.fdopen(os.open(source, os.O_RDONLY | os.O_NOFOLLOW), "rb") as input_file:
                    with destination.open("wb") as output:
                        shutil.copyfileobj(input_file, output)
                        output.flush()
                        os.fsync(output.fileno())
            self._write(staged / "record.json", {"revision": revision, "author": self.principal,
                        "created_at": time.time_ns(), "paths": paths, **metadata})
            # Persist directory entries before publishing a reference to this snapshot.
            for directory in sorted((path for path in staged.rglob("*") if path.is_dir()),
                                    key=lambda path: len(path.parts), reverse=True):
                self._sync_directory(directory)
            self._sync_directory(staged)
            os.rename(staged, snapshots / revision)
            self._sync_directory(snapshots)
            return revision
        finally:
            if staged.exists():
                shutil.rmtree(staged)

    def resolve_reference(self, repo_id, name="main"):
        _reference(name)
        with self._lock(repo_id) as repo:
            value = self._refs(repo).get(name)
            if value is None:
                raise RevisionNotFound(f"Unknown local reference: {name}")
            return ResolvedReference(value["revision"], generation=value["generation"])

    def resolve_revision(self, repo_id, revision):
        with self._lock(repo_id) as repo:
            value = None if _REVISION.fullmatch(revision) else self._refs(repo).get(revision)
            resolved = value["revision"] if value else revision
            self._read(self._snapshot_path(repo, resolved) / "record.json")
            return resolved

    def download_snapshot(self, repo_id, revision, local_dir, *, allow_patterns=None):
        resolved = self.resolve_revision(repo_id, revision)
        repo = self._repo(repo_id)
        snapshot = self._snapshot_path(repo, resolved)
        record = self._read(snapshot / "record.json")
        patterns = [allow_patterns] if isinstance(allow_patterns, str) else allow_patterns
        local_dir = Path(local_dir)
        if local_dir.resolve().is_relative_to(self.root.resolve()):
            raise ValueError("Download destination must be outside the local storage root")
        if local_dir.is_symlink():
            raise ValueError("Download destination cannot be a symlink")
        local_dir.mkdir(parents=True, exist_ok=True)
        for name in record["paths"]:
            if patterns is not None and not any(fnmatch.fnmatch(name, pattern) for pattern in patterns):
                continue
            source = _inside(snapshot / "files", name)
            destination = _inside(local_dir, name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporary = tempfile.mkstemp(prefix=".download-", dir=destination.parent)
            try:
                with os.fdopen(descriptor, "wb") as output:
                    with os.fdopen(os.open(source, os.O_RDONLY | os.O_NOFOLLOW), "rb") as input_file:
                        shutil.copyfileobj(input_file, output)
                    output.flush()
                    os.fsync(output.fileno())
                # Replacing, rather than truncating, also protects existing hardlinks.
                os.replace(temporary, destination)
                self._sync_directory(destination.parent)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)

    def initialize_repository(self, repo_id, folder, *, private):
        with self._lock(repo_id) as repo:
            if self._refs(repo):
                raise ValueError("Local repository already exists")
            revision = self._snapshot(repo, Path(folder), None, kind="global", participant=None)
            self._write(repo / "refs.json", {"main": {"revision": revision, "generation": 1}})
        return PublishResult(revision, resolved_revision=revision)

    def new_submission_revision(self, participant, source_round):
        return f"submission-{uuid.uuid4().hex}"

    def publish_submission(self, repo_id, folder, paths, *, participant, source_round,
                           base_revision, submission_revision):
        if participant != self.principal:
            raise ValueError("Participant must match the explicitly configured local principal")
        name = _reference(submission_revision or self.new_submission_revision(participant, source_round))
        if name == "main":
            raise ValueError("A submission cannot replace main")
        with self._lock(repo_id) as repo:
            refs = self._refs(repo)
            if "main" not in refs:
                raise ValueError("Initialize the local repository before submitting")
            if name in refs:
                raise ValueError("Submission reference already exists")
            base = self._read(self._snapshot_path(repo, base_revision) / "record.json")
            if base["kind"] != "global":
                raise ValueError("Submission base must be a global snapshot")
            revision = self._snapshot(repo, Path(folder), paths, kind="submission", participant=participant,
                                      base_revision=base_revision, source_round=source_round, submission_revision=name)
            refs[name] = {"revision": revision, "generation": 1}
            self._write(repo / "refs.json", refs)
        return PublishResult(name, resolved_revision=revision)

    @staticmethod
    def _candidate(record):
        return SubmissionCandidate(record["submission_revision"], record["revision"], record["author"], record["participant"])

    def discover_submissions(self, repo_id, *, context=None):
        if context is not None and context.repo_id != repo_id:
            raise ValueError("Round context belongs to a different repository")
        with self._lock(repo_id) as repo:
            revisions = {value["revision"] for value in self._refs(repo).values()}
            candidates = []
            for revision in revisions:
                record = self._read(self._snapshot_path(repo, revision) / "record.json")
                if record["kind"] == "submission" and (context is None or
                        record["base_revision"] == context.reference.revision):
                    candidates.append(self._candidate(record))
        return sorted(candidates, key=lambda value: value.identifier), []

    def explicit_submissions(self, repo_id, values):
        selected, seen = [], set()
        for value in values:
            revision = self.resolve_revision(repo_id, value)
            if revision in seen:
                raise ValueError("Duplicate submission selection")
            seen.add(revision)
            record = self._read(self._snapshot_path(self._repo(repo_id), revision) / "record.json")
            if record["kind"] != "submission":
                raise ValueError("Selected local revision is not a submission")
            selected.append(self._candidate(record))
        return selected

    def _set_tag(self, repo, tag, revision):
        _reference(tag)
        refs = self._refs(repo)
        if tag in refs:
            raise ValueError("Tag reference already exists")
        refs[tag] = {"revision": revision, "generation": 1}
        self._write(repo / "refs.json", refs)

    def publish_aggregate(self, repo_id, folder, paths, *, expected_base, next_round, tag,
                          reference=None, claim=None):
        if claim is not None:
            raise ValueError("Local storage does not support fenced coordination")
        if reference is not None and reference.revision != expected_base:
            raise ValueError("Publication reference differs from the expected base")
        with self._lock(repo_id) as repo:
            refs = self._refs(repo)
            current = refs.get("main")
            if current is None or current["revision"] != expected_base or (reference is not None and
                    reference.generation is not None and reference.generation != current["generation"]):
                raise ValueError("Local main changed before publication")
            revision = self._snapshot(repo, Path(folder), paths, kind="global", participant=None,
                                      base_revision=expected_base, round=next_round)
            refs["main"] = {"revision": revision, "generation": current["generation"] + 1}
            try:
                self._write(repo / "refs.json", refs)
            except OSError as exc:
                raise PublicationUncertain(
                    "Local publication may have succeeded; reconcile main before retrying"
                ) from exc
            warnings, tagged = (), None
            if tag:
                try:
                    self._set_tag(repo, tag, revision)
                    tagged = True
                except Exception as exc:
                    tagged = False
                    warnings = (f"Published {revision}, but tag {tag!r} failed: {exc}",)
        return PublishResult(revision, resolved_revision=revision, warnings=warnings, tag_created=tagged)
