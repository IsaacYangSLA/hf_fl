"""Sandbox-only worker entrypoint for managed FedAvg jobs.

Control-plane code must never import plugins to run work. This module delays all
HF2L training/checkpoint imports until a worker is explicitly executed.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import threading
import time

from .workflow import RuntimeConfig


class RuntimeSafetyError(RuntimeError):
    """Execution cannot continue without confirmed, job-bound state."""


class InitializationUncertain(RuntimeSafetyError):
    """Initial publication may have succeeded; an operator must reconcile it."""


class TargetRoundReached(Exception):
    """The absolute final round is already published."""


def _safe(path: Path) -> Path:
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            raise RuntimeSafetyError("Worker paths cannot contain symlinks")
    return path


def _read(path):
    from hf2l.common.fs import read_json
    return read_json(_safe(Path(path)))


def _write(path, value):
    from hf2l.common.fs import write_json
    write_json(_safe(Path(path)), value)


def _verify_source(config):
    root = _safe(Path(config.source_dir))
    if not root.is_dir():
        raise RuntimeSafetyError("The immutable source snapshot is unavailable")
    for name, expected in config.source_manifest.items():
        path = _safe(root / name)
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise RuntimeSafetyError("The source snapshot differs from its verified manifest")


def _install_built_artifacts(config):
    """Install verified wheels offline inside this component's private sandbox."""
    if not config.built_artifacts:
        return None
    import shutil
    import stat
    import subprocess
    from .domain import canonical_json
    _check_binding(config)
    build = _safe(Path(config.build_dir))
    if not build.is_dir():
        raise RuntimeSafetyError("The approved private build output is unavailable")
    expected_names = set(config.built_artifacts)
    actual_names = set()
    for path in build.iterdir():
        if path.name == "build-result.json":
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise RuntimeSafetyError("Private build metadata must be a regular immutable file")
            continue
        if not path.is_file() or path.is_symlink():
            raise RuntimeSafetyError("Private build outputs must be regular immutable wheels")
        actual_names.add(path.name)
    if actual_names != expected_names:
        raise RuntimeSafetyError("The private build directory differs from its approved wheel manifest")
    wheels = []
    for name, artifact in sorted(config.built_artifacts.items()):
        path = _safe(build / name)
        metadata = path.stat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or
                metadata.st_size != artifact.size_bytes):
            raise RuntimeSafetyError("Private wheel size or file ownership differs from its manifest")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != artifact.sha256:
            raise RuntimeSafetyError("Private wheel bytes differ from their approved build hash")
        wheels.append(path)
    state = Path(config.state_dir)
    target = _safe(state / "site-packages")
    marker = state / "private-build-install.json"
    identity = hashlib.sha256(canonical_json({
        "binding": config.durable_binding,
        "artifacts": {name: artifact.model_dump(mode="json")
                      for name, artifact in config.built_artifacts.items()},
    }).encode("utf-8")).hexdigest()

    def installed_files(root):
        result = {}
        total = 0
        for path in sorted(root.rglob("*")):
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise RuntimeSafetyError("Private installed modules cannot contain symlinks or hardlinks")
            total += metadata.st_size
            if len(result) >= 100000 or total > 1 << 40:
                raise RuntimeSafetyError("Private installed modules exceed the bounded manifest")
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            result[path.relative_to(root).as_posix()] = {
                "sha256": digest.hexdigest(), "size_bytes": metadata.st_size}
        return result

    if marker.exists():
        saved = _read(marker)
        if saved.get("identity") != identity:
            raise RuntimeSafetyError("Private installed modules belong to a different build")
        if saved.get("phase") == "installed":
            if not target.is_dir() or installed_files(target) != saved.get("files"):
                raise RuntimeSafetyError("Private installed module bytes changed")
            return target
        if saved.get("phase") != "installing":
            raise RuntimeSafetyError("Invalid private build installation state")
        # No plugin can start until the durable installed marker is written.
        if target.exists():
            shutil.rmtree(target)
    elif target.exists():
        raise RuntimeSafetyError("Private modules exist without a verified installation marker")
    _write(marker, {"identity": identity, "phase": "installing"})
    with tempfile.TemporaryDirectory(prefix=".built-install-", dir=state) as directory:
        stage = Path(directory) / "site-packages"
        scratch = Path(directory) / "tmp"
        scratch.mkdir()
        environment = {"PATH": os.defpath, "PIP_CONFIG_FILE": os.devnull,
                       "PIP_DISABLE_PIP_VERSION_CHECK": "1", "TMPDIR": str(scratch)}
        arguments = [sys.executable, "-I", "-m", "pip", "install", "--no-index", "--no-deps",
                     "--no-compile", "--no-input", "--disable-pip-version-check", "--no-cache-dir",
                     "--target", str(stage), *map(str, wheels)]
        result = subprocess.run(arguments, env=environment, cwd=directory,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=min(300, config.spec.max_duration_seconds), check=False)
        if result.returncode != 0:
            raise RuntimeSafetyError("The sandbox could not install its approved offline wheels")
        files = installed_files(stage)
        stage.rename(target)
        _write(marker, {"identity": identity, "phase": "installed", "files": files})
    return target


def _load_plugin(config):
    _verify_source(config)
    private = _install_built_artifacts(config)
    if private is not None:
        # Imports must preserve the exact installed-file manifest across retries.
        sys.dont_write_bytecode = True
        os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
        if str(private) not in sys.path:
            sys.path.insert(0, str(private))
    root = str(Path(config.source_dir))
    if root not in sys.path:
        sys.path.insert(0, root)
    from hf2l.common.output import plugin_stdout_to_stderr
    from hf2l.plugin_loader import BUILTIN_PLUGINS, load_plugin
    value = config.spec.plugin
    with plugin_stdout_to_stderr():
        if value in BUILTIN_PLUGINS:
            plugin = load_plugin(value)
        else:
            module, separator, entry = value.partition(":")
            plugin = importlib.import_module(module)
            origin = getattr(plugin, "__file__", None)
            allowed = [Path(root).resolve(), *([private.resolve()] if private is not None else [])]
            if not origin or not any(Path(origin).resolve().is_relative_to(path) for path in allowed):
                raise RuntimeSafetyError("A job plugin must come from its immutable source or verified private build")
            if separator:
                plugin = getattr(plugin, entry)
    return plugin


def make_managed_store(config):
    from hf2l.backends.exchange import ExchangeStore
    from hf2l_exchange.client import ExchangeClient
    # The trusted proxy holds upstream tokens and mTLS keys. No human credentials,
    # origin URLs, signing keys or broad storage credentials enter this process.
    client = ExchangeClient.for_execution(
        config.proxy_socket, space=config.space_id,
    )
    return ExchangeStore(None, config.exchange_endpoint, client=client)


def _main_document(store, config):
    from hf2l.core.ports import RevisionNotFound
    from hf2l.core.protocol import ROUND_FILE, RoundRecord
    try:
        reference = store.resolve_reference(config.space_id, "main")
    except Exception as exc:
        if isinstance(exc, RevisionNotFound) or getattr(exc, "status", None) == 404:
            return None
        raise
    with tempfile.TemporaryDirectory(prefix=".round-", dir=config.state_dir) as directory:
        folder = Path(directory)
        store.download_snapshot(config.space_id, reference.revision, folder, allow_patterns=ROUND_FILE)
        document = RoundRecord.from_dict(_read(folder / ROUND_FILE))
        if document.schema_version >= 2 and document.to_dict().get("backend") != store.name:
            raise RuntimeSafetyError("The published round declares another backend")
        return reference.revision, document.to_dict()


def _check_binding(config):
    state = _safe(Path(config.state_dir))
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = state / "worker-binding.json"
    if path.exists():
        if _read(path) != config.durable_binding:
            raise RuntimeSafetyError("Writable worker state belongs to a different job or specification")
    else:
        if any(p.name not in (".worker.lock", "runtime.json", "worker.json") for p in state.iterdir()):
            raise RuntimeSafetyError("Worker artifacts exist without their durable identity")
        _write(path, config.durable_binding)


def initialize_once(store, config, plugin=None, on_event=None):
    """Initialize once, preserving bytes and intent across lost acknowledgments.

An uncertain request never causes an automatic second publication. A retry can
only acknowledge a currently published initial model whose manifest and hashes
exactly match the saved intent. Missing or changed publication remains fenced.
"""
    from hf2l.checkpoint_utils import discover_checkpoint
    from hf2l.common.fs import artifact_hashes, utc_now
    from hf2l.common.output import plugin_stdout_to_stderr
    from hf2l.core.protocol import AlgorithmSpec, ROUND_FILE, SCHEMA_VERSION, RoundRecord
    from hf2l.init_repo import generic_model_card
    from hf2l.plugin_loader import require_callable

    _check_binding(config)
    state = Path(config.state_dir)
    intent_path = state / "initialization.json"
    folder = state / "initial-model"
    current = _main_document(store, config)
    saved = _read(intent_path) if intent_path.exists() else None
    if saved:
        if saved.get("binding") != config.durable_binding:
            raise RuntimeSafetyError("Initial publication intent belongs to another job")
        if saved.get("phase") == "published":
            if current is None:
                raise InitializationUncertain("The confirmed initial reference disappeared")
            return saved["revision"]
        if not folder.is_dir():
            raise InitializationUncertain("Initial publication artifacts are missing")
        document_path = _safe(folder / ROUND_FILE)
        if hashlib.sha256(document_path.read_bytes()).hexdigest() != saved.get("manifest_sha256"):
            raise InitializationUncertain("Initial publication manifest changed")
        try:
            checkpoint = discover_checkpoint(_safe(folder))
        except (OSError, ValueError) as exc:
            raise InitializationUncertain("Initial publication checkpoint is invalid") from exc
        if artifact_hashes(folder, checkpoint.artifact_paths) != saved.get("checkpoint_files_sha256"):
            raise InitializationUncertain("Initial publication checkpoint changed")
        if current:
            revision, document = current
            expected = _read(document_path)
            if document != expected:
                raise InitializationUncertain("The current main does not prove the saved initial publication")
            with tempfile.TemporaryDirectory(prefix=".initial-check-", dir=state) as temporary:
                snapshot = Path(temporary)
                store.download_snapshot(config.space_id, revision, snapshot)
                actual = discover_checkpoint(snapshot)
                if artifact_hashes(snapshot, actual.artifact_paths) != saved["checkpoint_files_sha256"]:
                    raise InitializationUncertain("The published initial model differs from saved bytes")
            saved.update(phase="published", revision=revision, reconciled=True)
            _write(intent_path, saved)
            return revision
        if saved.get("phase") in ("publishing", "uncertain"):
            proof = _resolution(config, "init", saved)
            if proof and proof.action == "absent":
                _verify_absent(store, config, proof, _read(document_path), "model.global")
                saved["phase"] = "prepared"
                _write(intent_path, saved)
            else:
                raise InitializationUncertain("Initial publication outcome is unknown; no automatic replay is allowed")
        if saved.get("phase") != "prepared":
            raise RuntimeSafetyError("Invalid initial publication state")
    else:
        if current:
            raise InitializationUncertain("A main reference exists without this worker's initial publication intent")
        if folder.exists():
            raise RuntimeSafetyError("Initial model artifacts exist without publication intent")
        folder.mkdir(mode=0o700)
        plugin = plugin or _load_plugin(config)
        options = _training_options(config)
        options["repo_id"] = config.space_id
        with plugin_stdout_to_stderr():
            metadata = require_callable(plugin, "initialize_model")(folder, options)
        if metadata is None:
            metadata = {}
        if not isinstance(metadata, dict):
            raise RuntimeSafetyError("Initializer must return a JSON metadata object")
        json.dumps(metadata, allow_nan=False)
        checkpoint = discover_checkpoint(folder)
        if not (folder / "README.md").exists():
            (folder / "README.md").write_text(generic_model_card(config.space_id), encoding="utf-8")
        hashes = artifact_hashes(folder, checkpoint.artifact_paths)
        document = RoundRecord.from_dict({
            "schema_version": SCHEMA_VERSION, "backend": store.name, "round": 0,
            "algorithm": "initial model", "algorithm_spec": AlgorithmSpec("fedavg").to_dict(),
            "created_at": utc_now(), "checkpoint_files": list(checkpoint.artifact_paths),
            "checkpoint_files_sha256": hashes,
            "initialization": {"source": "managed_job", "job_id": config.job_id,
                               "spec_digest": config.spec_digest, "metadata": metadata},
            "submissions": [],
        }).to_dict()
        _write(folder / ROUND_FILE, document)
        saved = {"binding": config.durable_binding, "phase": "prepared",
                 "manifest_sha256": hashlib.sha256((folder / ROUND_FILE).read_bytes()).hexdigest(),
                 "checkpoint_files_sha256": hashes}
        _write(intent_path, saved)
    saved["phase"] = "publishing"
    _write(intent_path, saved)
    if on_event:
        on_event("publishing")
    try:
        result = store.initialize_repository(config.space_id, folder, private=True)
    except Exception as exc:
        saved.update(phase="uncertain", error_type=type(exc).__name__)
        _write(intent_path, saved)
        if on_event:
            on_event("uncertain")
        raise InitializationUncertain("Initial publication requires reconciliation") from exc
    saved.update(phase="published", revision=result.resolved_revision or result.revision)
    _write(intent_path, saved)
    if on_event:
        on_event("published")
    return saved["revision"]


def _resolution(config, role, document):
    from .workflow import publication_intent_fingerprint
    proof = next((p for p in config.reconciliation if p.role == role), None)
    if proof is not None and proof.intent_sha256 != publication_intent_fingerprint(role, document):
        raise RuntimeSafetyError("Reconciliation proof does not identify the retained publication intent")
    return proof


def _verify_confirmed(store, config, proof, folder, manifest_name):
    from hf2l.common.fs import artifact_hashes
    from hf2l.checkpoint_utils import discover_checkpoint
    from hf2l.core.protocol import ROUND_FILE
    expected = _read(folder / manifest_name)
    if store.resolve_revision(config.space_id, proof.record_id) != proof.record_id:
        raise RuntimeSafetyError("Reconciliation must select an immutable published record")
    with tempfile.TemporaryDirectory(prefix=".reconciliation-", dir=config.state_dir) as temporary:
        snapshot = Path(temporary)
        store.download_snapshot(config.space_id, proof.record_id, snapshot)
        document = _read(snapshot / manifest_name)
        full = snapshot / "fedavg_round-full.json"
        if manifest_name == ROUND_FILE and document.get("complete_manifest") and full.is_file():
            document = _read(full)
        if document != expected:
            raise RuntimeSafetyError("Confirmed record does not match the retained publication manifest")
        checkpoint = discover_checkpoint(snapshot)
        if artifact_hashes(snapshot, checkpoint.artifact_paths) != expected.get("checkpoint_files_sha256"):
            raise RuntimeSafetyError("Confirmed record checkpoint differs from retained publication bytes")
    if manifest_name == ROUND_FILE:
        current = _main_document(store, config)
        if current is None or current[0] != proof.record_id:
            raise RuntimeSafetyError("A published global record is not proof of its main reference commit")
    if proof.role == "owner" and store.capabilities.requires_coordination_for_publication:
        if not proof.acquisition_id:
            raise RuntimeSafetyError("Owner confirmation requires its fenced acquisition identifier")
        acquisition = store.client.get_acquisition(config.space_id, proof.acquisition_id)
        if acquisition.state != "completed" or acquisition.result_record_id != proof.record_id:
            raise RuntimeSafetyError("The fenced acquisition does not confirm the selected publication")


def _verify_absent(store, config, proof, expected, kind):
    # The trusted configuration contains durable revocation/termination operation
    # IDs. It is installed only by the manager; no job or public request selects it.
    if not proof.grants_revoked or not proof.termination_confirmed:
        raise RuntimeSafetyError("An absent publication requires old execution fencing")
    client = getattr(store, "client", None)
    if client is None:
        # Test transport uses the authoritative immutable reference/manifest.
        current = _main_document(store, config)
        if kind == "model.global" and current and current[1] == expected:
            raise RuntimeSafetyError("A confirmed publication cannot be reconciled as absent")
        return
    if proof.record_id:
        try:
            record = client.get_record(config.space_id, proof.record_id)
        except Exception as exc:
            if getattr(exc, "status", None) != 404:
                raise
        else:
            if record.state == "published":
                if kind != "model.global":
                    raise RuntimeSafetyError("A published submission cannot be reconciled as absent")
                current = _main_document(store, config)
                if current and current[0] == proof.record_id:
                    raise RuntimeSafetyError("Main already confirms the allegedly absent publication")
    # A lost create acknowledgment can leave a record ID missing locally.
    # Check published descriptors under the current grant after the fencing barrier.
    manifest_name = "fedavg_round.json" if kind == "model.global" else "fedavg_submission.json"
    for record in client.records(config.space_id, kind=kind, state="published"):
        manifest = record.metadata.get("hf2l_files", {}).get(manifest_name, {})
        if kind == "training.update":
            same = manifest == expected
        else:
            same = (manifest.get("base_revision") == expected.get("base_revision") and
                    manifest.get("round") == expected.get("round") and
                    manifest.get("checkpoint_files_sha256") == expected.get("checkpoint_files_sha256"))
        if same:
            if kind == "training.update":
                raise RuntimeSafetyError("A matching published submission invalidates absence evidence")
            current = _main_document(store, config)
            if current and current[0] == record.id:
                raise RuntimeSafetyError("A matching published main invalidates absence evidence")


def _replay_owner(listener, config, job):
    """Publish the same retained aggregate, without rerunning aggregation."""
    from dataclasses import asdict
    from hf2l.common.fs import checked_file_paths, artifact_hashes
    from hf2l.checkpoint_utils import discover_checkpoint
    from hf2l.core.ports import ClaimInactive, ResolvedReference, RoundContext
    from hf2l.fedavg_runner import ClaimRenewal, RunState
    intent = job["publication_intent"]
    folder = _safe(Path(intent["aggregate_dir"]))
    root = Path(config.state_dir)
    if root not in folder.parents:
        raise RuntimeSafetyError("Retained aggregate lies outside this component's state")
    manifest_path = folder / "fedavg_round.json"
    if hashlib.sha256(manifest_path.read_bytes()).hexdigest() != intent["manifest_sha256"]:
        raise RuntimeSafetyError("Retained aggregate manifest changed before reconciliation")
    expected = _read(manifest_path)
    checkpoint = discover_checkpoint(folder)
    if artifact_hashes(folder, checkpoint.artifact_paths) != expected["checkpoint_files_sha256"]:
        raise RuntimeSafetyError("Retained aggregate checkpoint changed before reconciliation")
    reference = ResolvedReference(**intent["base"])
    if listener.store.resolve_reference(config.space_id, "main") != reference:
        raise RuntimeSafetyError("The owner base changed; the retained aggregate cannot be replayed")
    context = RoundContext(config.space_id, reference, intent["source_round"])
    claim, renewal, run_state = None, None, None
    try:
        if listener.store.capabilities.requires_coordination_for_publication:
            path = listener._job_dir(job) / "claim-state.json"
            run_state = RunState(path)
            saved = run_state.acquire(context, listener.config.claim_lease_seconds)
            def acquire():
                return listener.store.acquire_claim(
                    config.space_id, context=context, acquisition_key=saved["acquisition_key"],
                    claim_id=saved.get("claim_id"), lease_seconds=saved["lease_seconds"])
            try:
                claim = acquire()
            except ClaimInactive:
                saved = run_state.restart()
                claim = acquire()
            used = {item["resolved_revision"] for item in expected["submissions"]}
            if not used <= set(claim.input_ids):
                raise RuntimeSafetyError("A successor claim does not contain the retained aggregate's inputs")
            run_state.remember(claim)
            renewal = ClaimRenewal(listener.store, config.space_id, claim, saved["lease_seconds"], run_state)
            renewal.start()
            renewal.check()
        listener._set_status(job, "publishing")
        listener._emit("publishing", job)
        result = listener.store.publish_aggregate(
            config.space_id, folder, checked_file_paths(folder),
            expected_base=reference.revision, next_round=intent["target_round"],
            tag=None, reference=reference, claim=renewal.claim if renewal else claim)
        if run_state:
            run_state.clear()
        listener._finish(job, "published", result={"publication": asdict(result)}, reconciled=True)
    except Exception as exc:
        listener._set_status(job, "uncertain")
        from hf2l.listener.engine import UncertainOperation
        raise UncertainOperation("Retained aggregate replay requires reconciliation") from exc
    finally:
        if renewal:
            renewal.close()
        if run_state:
            run_state.close()


def reconcile_listener(listener, config):
    """Apply exact retained intent evidence after durable old-attempt fencing."""
    from hf2l.core.protocol import SUBMISSION_FILE, ROUND_FILE
    job = listener.state["jobs"].get(listener.state["active"])
    if not job or job["status"] not in listener.uncertain_statuses:
        return
    role = "client" if config.role == "client" else "owner"
    if role == "client":
        folder = listener._job_dir(job) / "work/trained_model"
        document = _read(folder.parent / "client-publication-intent.json")
        manifest_name = SUBMISSION_FILE
    else:
        document = job
        intent = job.get("publication_intent")
        if not intent:
            return
        folder = Path(intent["aggregate_dir"])
        manifest_name = ROUND_FILE
    proof = _resolution(config, role, document)
    if proof is None:
        return
    if proof.action == "confirmed":
        _verify_confirmed(listener.store, config, proof, folder, manifest_name)
        listener.resolve_uncertain("submitted" if role == "client" else "published")
    else:
        expected = _read(folder / manifest_name)
        _verify_absent(listener.store, config, proof, expected,
                       "training.update" if role == "client" else "model.global")
        if role == "client":
            listener.resolve_uncertain("retry")
        else:
            _replay_owner(listener, config, job)


def _training_options(config):
    options = config.spec.to_dict()["options"]
    # Job payloads cannot select host or another participant's local dataset.
    if any(key in options for key in ("dataset_npz", "eval_npz", "data_path", "dataset_path")):
        raise RuntimeSafetyError("Dataset filesystem paths must come from locally approved bindings")
    if config.role == "client":
        participant = next(p for p in config.spec.participants if p.participant_id == config.participant_id)
        binding = config.dataset_bindings[participant.dataset_binding]
        if binding.kind == "npz":
            _safe(Path(binding.path))
            options["dataset_npz"] = binding.path
    if config.secret_options_file:
        import stat
        path = _safe(Path(config.secret_options_file))
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > 65536:
            raise RuntimeSafetyError("Private secret options must be a bounded regular file")
        secret = _read(path)
        expected_role = "participant" if config.role == "client" else "owner"
        expected = {"schema_version": 1, "job_id": config.job_id, "attempt_id": config.attempt_id,
                    "component_id": config.component_id, "epoch": config.epoch, "role": expected_role}
        if (set(secret) != set(expected) | {"options", "references"} or
                any(secret.get(key) != value for key, value in expected.items()) or
                not isinstance(secret["options"], dict) or not isinstance(secret["references"], dict) or
                set(secret["options"]) != set(config.secret_option_names) or
                set(secret["references"]) != set(config.secret_option_names) or
                any(config.spec.secret_refs[key] != value for key, value in secret["references"].items())):
            raise RuntimeSafetyError("Private secret options do not match this component's approved references")
        if set(secret["options"]) & {"repo_id", "participant", "dataset_npz", "eval_npz", "data_path", "dataset_path", "source_dir", "state_dir", "minimum_participants"}:
            raise RuntimeSafetyError("Secret references cannot override trusted resource or dataset bindings")
        json.dumps(secret["options"], allow_nan=False)
        options.update(secret["options"])
    return options


def make_listener(store, config, plugin=None, on_event=None):
    """Construct a listener that can never produce a round past the job target."""
    from hf2l.listener.client import ClientListener
    from hf2l.listener.owner import OwnerListener
    from hf2l.plugin_loader import require_callable
    from hf2l.round.config import RoundConfig

    target = config.spec.target_round

    class BoundedOwner(OwnerListener):
        def _probe(self, revision):
            probe = super()._probe(revision)
            if probe.round_number >= target:
                raise TargetRoundReached()
            return probe

    class BoundedClient(ClientListener):
        def _round_metadata(self, revision):
            number = super()._round_metadata(revision)
            if number >= target:
                raise TargetRoundReached()
            return number

    state = Path(config.state_dir)
    if config.role == "client":
        plugin = plugin or _load_plugin(config)
        return BoundedClient(
            store, repo_id=config.space_id, participant=config.participant_id,
            state_dir=state / "listener", source_id=config.source_identity,
            training_id=config.spec_digest, train_model=require_callable(plugin, "train_model"),
            options=_training_options(config), on_event=on_event,
        )
    # The generic FedAvg runner needs no plugin import to aggregate model arrays.
    # Its fixed immutable participant allowlist is generated from the job spec.
    allowlist = state / "participants.json"
    expected = {principal: participant for participant, principal in config.participant_principals.items()}
    if allowlist.exists():
        if _read(allowlist) != expected:
            raise RuntimeSafetyError("The immutable participant allowlist changed")
    else:
        _write(allowlist, expected)
    minimum = config.spec.to_dict()["options"].get("minimum_participants", 2)
    owner_config = RoundConfig(
        repo_id=config.space_id, output_dir=state / "unused",
        allowlist=allowlist if expected else None, minimum_participants=minimum,
        array_backend="numpy", publish=True,
    )
    return BoundedOwner(store, config=owner_config, state_dir=state / "listener",
                        source_id=config.source_identity, on_event=on_event)


def run_worker(config, *, store=None, stop_event=None, once=False):
    """Run one isolated component with durable progress and absolute completion."""
    from hf2l.listener.engine import ListenerStateError, UncertainOperation
    root = _safe(Path(config.state_dir))
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    import fcntl
    descriptor = os.open(_safe(root / ".worker.lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    lock = os.fdopen(descriptor, "a+b")
    owned = store is None
    stop = stop_event or threading.Event()
    started = time.monotonic()
    bound = False
    status = {"schema_version": 1, "job_id": config.job_id, "attempt_id": config.attempt_id,
              "component_id": config.component_id, "epoch": config.epoch,
              "target_round": config.spec.target_round, "role": config.role,
              "participant_id": config.participant_id, "metrics": {}, "publication_status": "none"}

    def metrics(value):
        import math
        if not isinstance(value, dict):
            return {}
        import re
        return {key: number for key, number in list(value.items())[:32]
                if isinstance(key, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", key)
                and type(number) in (int, float) and abs(number) <= 1e100 and math.isfinite(number)}

    def progress(phase, **fields):
        status.update(phase=phase, observed_at=time.time(), **fields)
        if phase == "publishing":
            status["publication_status"] = "publishing"
        elif phase in {"uncertain", "needs_attention"}:
            status["publication_status"] = "unknown"
        elif phase in {"published", "submitted", "completed", "initialized"}:
            status["publication_status"] = "confirmed"
        elif phase == "retry_authorized":
            status["publication_status"] = "absent"
        status["readiness"] = {
            "initializing": "initializing", "training": "training",
            "ready": "ready", "publishing": "ready", "submitted": "ready",
            "completed": "finished", "failed": "failed",
            "needs_attention": "failed", "duration_exceeded": "failed",
        }.get(phase, "waiting")
        if bound:
            _write(root / "progress.json", status)
            _write(root / "runtime-status.json", status)
        print(json.dumps(status, sort_keys=True, allow_nan=False), flush=True)

    def event(details):
        # Listener events contain bounded protocol facts; no option/token values.
        allowed = {key: value for key, value in details.items()
                   if key in {"event", "source_round", "status", "eligible_count",
                              "minimum_participants", "retry_seconds", "error_type", "attempt"}}
        progress(allowed.pop("event", "running"), **allowed)

    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeSafetyError("Another worker owns this component's state") from exc
        _check_binding(config)
        bound = True
        status_path = root / "runtime-status.json"
        if status_path.exists():
            previous = _read(status_path)
            if previous.get("job_id") != config.job_id or previous.get("component_id") != config.component_id:
                raise RuntimeSafetyError("Saved telemetry belongs to another component")
            status["metrics"] = metrics(previous.get("metrics", {}))
            if type(previous.get("source_round")) is int and previous["source_round"] >= 0:
                status["source_round"] = previous["source_round"]
        _verify_source(config)
        _training_options(config)
        store = store or make_managed_store(config)
        if config.role in ("owner", "init"):
            progress("initializing")
            initialize_once(store, config, on_event=lambda phase: progress(
                "initializing", publication_status={"publishing": "publishing", "uncertain": "unknown",
                                                     "published": "confirmed"}[phase]))
            if config.role == "init":
                progress("initialized", current_round=0)
                return 0
        delay = config.poll_interval
        with make_listener(store, config, on_event=event) as listener:
            reconcile_listener(listener, config)
            while not stop.is_set():
                if (time.monotonic() - started >= config.spec.max_duration_seconds or
                        config.deadline_at is not None and time.time() >= config.deadline_at):
                    progress("duration_exceeded")
                    return 3
                current = _main_document(store, config)
                if current is None:
                    progress("waiting_initialization")
                    if once:
                        return 0
                    stop.wait(config.poll_interval)
                    continue
                revision, document = current
                current_round = document["round"]
                status["current_round"] = current_round
                status["revision"] = revision
                if config.role == "owner" and isinstance(document.get("evaluation"), dict):
                    status["metrics"] = metrics(document["evaluation"])
                if current_round >= config.spec.target_round:
                    # A saved uncertain publication must be reconciled even if
                    # main advanced; reaching target alone does not clear intent.
                    active = listener.state["jobs"].get(listener.state["active"])
                    if active and active["status"] in listener.uncertain_statuses:
                        raise UncertainOperation("Saved publication still requires explicit reconciliation")
                    progress("completed", current_round=current_round, revision=revision)
                    return 0
                try:
                    outcome = listener.poll_once()
                except TargetRoundReached:
                    continue
                except (ListenerStateError, UncertainOperation):
                    raise
                except Exception as exc:
                    progress("retry", current_round=current_round, error_type=type(exc).__name__, retry_seconds=delay)
                    if once:
                        raise
                    stop.wait(delay)
                    delay = min(delay * 2, config.max_backoff)
                    continue
                delay = config.poll_interval
                if config.role == "owner" and outcome == "published":
                    latest = _main_document(store, config)
                    if latest:
                        status["current_round"] = current_round = latest[1]["round"]
                        status["revision"] = latest[0]
                if config.role == "client":
                    job = listener.state["jobs"].get(revision)
                    if job and job["status"] in {"ready", "publishing", "submitted"}:
                        result_file = listener._job_dir(job) / "training-result.json"
                        if result_file.exists():
                            training = _read(result_file).get("training", {})
                            status["metrics"] = metrics(training.get("metrics", {}))
                            status["source_round"] = job["source_round"]
                progress(outcome, current_round=current_round)
                if once:
                    return 0
                stop.wait(config.poll_interval)
        progress("stopped")
        return 0
    except (InitializationUncertain, UncertainOperation) as exc:
        progress("needs_attention", error_type=type(exc).__name__)
        return 4
    except Exception as exc:
        progress("failed", error_type=type(exc).__name__)
        raise
    finally:
        if owned and store is not None:
            # An injected SDK client belongs to this worker, not ExchangeStore.
            store.close()
            client = getattr(store, "client", None)
            if client is not None:
                client.close()
        lock.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    stop = threading.Event()
    for name in (signal.SIGTERM, signal.SIGINT):
        signal.signal(name, lambda *_: stop.set())
    try:
        path = _safe(args.config)
        if not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise RuntimeSafetyError("Worker configuration must be a bounded regular file")
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError("Duplicate runtime configuration key")
                result[key] = value
            return result
        def nonfinite(value):
            raise ValueError("Non-finite runtime configuration")
        document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs, parse_constant=nonfinite)
        if not isinstance(document, dict):
            raise RuntimeSafetyError("Worker configuration must be a JSON object")
        if document.get("role") == "build":
            from .build import BuildConfig, run_worker as run_build_worker
            return run_build_worker(BuildConfig.model_validate(document))
        config = RuntimeConfig.model_validate(document)
        return run_worker(config, stop_event=stop)
    except Exception as exc:
        print(json.dumps({"phase": "failed", "error_type": type(exc).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
