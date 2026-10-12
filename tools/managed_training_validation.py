"""Real LeNet job fixtures and assertions shared by opt-in system validation.

This is a validation tool, not an execution backend. Production training remains
inside the qualified node executor; no manager process imports this plugin.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from hf2l_jobs.domain import JobSpec


PLUGIN = '''"""Job-private real LeNet plugin with runtime isolation evidence."""
import errno
import json
import os
from pathlib import Path
import socket
from hf2l.plugins import lenet_poc

JOB_MARKER = {marker!r}
FOREIGN_PATH = {foreign!r}

def _probe():
    evidence = {{"job_marker": JOB_MARKER}}
    assert Path(__file__).parent == Path("/job/source")
    assert (Path("/job/source") / "job-marker.txt").read_text() == JOB_MARKER
    for path in (FOREIGN_PATH, "/job/foreign/job-marker.txt", "/run/hf2l/foreign.sock"):
        try:
            Path(path).read_bytes()
        except (FileNotFoundError, PermissionError, IsADirectoryError):
            continue
        raise AssertionError("Another job's host resources became visible")
    evidence["foreign_resources_denied"] = True
    try:
        Path("/job/source/unauthorized-write").write_text("forbidden")
    except OSError as exc:
        assert exc.errno in (errno.EACCES, errno.EROFS)
    else:
        raise AssertionError("Immutable source became writable")
    evidence["source_read_only"] = True
    for key in ("EXCHANGE_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "HF_TOKEN"):
        assert not os.environ.get(key)
    assert not Path("/var/run/docker.sock").exists()
    evidence["upstream_credentials_absent"] = True
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.settimeout(.2)
    try:
        connection.connect(("127.0.0.1", 32775))
    except OSError:
        evidence["direct_storage_network_denied"] = True
    else:
        raise AssertionError("Storage became directly reachable")
    finally:
        connection.close()
    assert Path("/run/hf2l/proxy.sock").exists()
    evidence["assigned_proxy_present"] = True
    Path("/job/state/isolation.json").write_text(json.dumps(evidence, sort_keys=True))

def initialize_model(output_dir, options):
    _probe()
    return lenet_poc.initialize_model(output_dir, options)

def train_model(base_dir, output_dir, options):
    _probe()
    return lenet_poc.train_model(base_dir, output_dir, options)
'''


def write_source_repository(directory, name, foreign_path):
    """Create a task-owned private source repository for registry approval."""
    root = Path(directory).absolute()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    (root / "managed_training_plugin.py").write_text(
        PLUGIN.format(marker=name, foreign=str(foreign_path)), encoding="utf-8")
    (root / "job-marker.txt").write_text(name, encoding="utf-8")
    commands = (("init", "-q"), ("add", "."),
                ("-c", "user.name=HF2L synthetic validation", "-c", "user.email=synthetic@example.invalid",
                 "commit", "-q", "-m", "Private synthetic LeNet validation source"))
    for arguments in commands:
        subprocess.run(["git", "-C", str(root), *arguments], check=True, capture_output=True, text=True)
    commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True,
                            capture_output=True, text=True).stdout.strip()
    manifest = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in root.iterdir() if path.is_file()}
    return {"root": str(root), "commit": commit, "manifest": manifest}


def job_spec(name, source_commit, runtime_image, pool_id, *, source_id="approved-source",
             target_round=2, seed=7):
    """Three managed components execute two complete real CPU FedAvg rounds."""
    resources = {"pool_id": pool_id, "cpu_millicores": 500,
                 "memory_bytes": 768 * 1024 ** 2, "disk_bytes": 64 * 1024 ** 2}
    components = [{"component_id": "owner", "role": "owner", "resources": resources}]
    components += [{"component_id": "client-" + participant, "role": "participant",
                    "participant_id": participant, "resources": resources}
                   for participant in ("alice", "bob")]
    return JobSpec.model_validate({
        "project_id": "test", "name": name, "source_id": source_id,
        "source_commit": source_commit, "runtime_image": runtime_image,
        "plugin": "managed_training_plugin", "options": {
            "seed": seed, "epochs": 1, "synthetic_examples": 8,
            "batch_size": 4, "learning_rate": 0.02, "device": "cpu",
            "minimum_participants": 2},
        "participants": [{"participant_id": participant, "dataset_binding": "synthetic-" + participant,
                          "mode": "managed", "component_id": "client-" + participant}
                         for participant in ("alice", "bob")],
        "components": components, "target_round": target_round,
        "max_duration_seconds": 900})


def _manifest(record, filename):
    value = record.metadata.get("hf2l_files", {}).get(filename)
    if not isinstance(value, dict):
        raise AssertionError("The published record has no inline workflow manifest")
    return value


def _checkpoint_hashes(record, document):
    advertised = document["checkpoint_files_sha256"]
    attachments = {item.path: item for item in record.attachments}
    assert isinstance(advertised, dict) and advertised
    assert all(isinstance(path, str) and isinstance(digest, str)
               and len(digest) == 64 for path, digest in advertised.items())
    assert set(advertised).issubset(attachments)
    if "checkpoint_files" in document:
        assert set(advertised) == set(document["checkpoint_files"])
    for path, digest in advertised.items():
        assert attachments[path].state == "verified"
        assert attachments[path].sha256 == digest
    return advertised


def verify_job_completed(admin, space_id, target_round, *, store=None):
    """Verify actual records, private lineage, hashes and optional model arithmetic.

    Passing the job-bound ExchangeStore enables byte retrieval through its real
    execution UDS. Without it, the trusted server-verified attachment digests and
    all published workflow manifests are checked; arithmetic is not claimed.
    """
    from hf2l.core.protocol import ROUND_FILE, SUBMISSION_FILE
    reference = admin.resolve(space_id, "main")
    globals_ = list(admin.records(space_id, kind="model.global", state="published"))
    updates = list(admin.records(space_id, kind="training.update", state="published"))
    rounds = {_manifest(record, ROUND_FILE)["round"]: record for record in globals_}
    assert len(rounds) == len(globals_) == target_round + 1
    assert set(rounds) == set(range(target_round + 1))
    assert reference.record_id == rounds[target_round].id
    assert len(updates) == 2 * target_round
    records = {record.id: record for record in (*globals_, *updates)}
    assert all(record.space_id == space_id for record in records.values())
    hashes = {}
    for number, record in sorted(rounds.items()):
        document = _manifest(record, ROUND_FILE)
        hashes[number] = _checkpoint_hashes(record, document)
        if number == 0:
            assert document["initialization"]["source"] == "managed_job"
            continue
        assert record.metadata["base_record_id"] == rounds[number - 1].id
        submissions = document["submissions"]
        assert {item["participant"] for item in submissions} == {"alice", "bob"}
        assert len(submissions) == 2
        assert sum(item["num_examples"] for item in submissions) == 16
        assert {item["coefficient"] for item in submissions} == {0.5}
        assert set(record.metadata["inputs"]) == {item["resolved_revision"] for item in submissions}
        for item in submissions:
            update = records[item["resolved_revision"]]
            submission = _manifest(update, SUBMISSION_FILE)
            assert update.kind == "training.update"
            assert update.metadata["base_record_id"] == rounds[number - 1].id
            assert submission["base_revision"] == rounds[number - 1].id
            assert submission["source_round"] == number - 1
            assert submission["participant"] == update.creator_bindings["participant"] == item["participant"]
            assert submission["num_examples"] == update.metadata["sample_count"] == item["num_examples"] == 8
            assert submission["training"]["hyperparameters"]["epochs"] == 1
            assert submission["training"]["dataset"].startswith("synthetic")
            _checkpoint_hashes(update, submission)
        assert hashes[number] != hashes[number - 1]
    result = {"space_id": space_id, "main": reference.record_id, "reference_token": reference.token,
              "rounds": target_round, "global_models": len(globals_), "training_updates": len(updates),
              "real_training_epochs": 2 * target_round, "examples_per_update": 8,
              "initial_hashes": hashes[0], "final_hashes": hashes[target_round],
              "verified_workflow_lineage": True, "verified_server_blob_digests": True,
              "verified_downloaded_bytes": False, "verified_fedavg_arithmetic": False}
    if store is not None:
        import numpy as np
        from safetensors.numpy import load_file
        from hf2l.common.fs import artifact_hashes
        from hf2l.checkpoint_utils import discover_checkpoint
        maximum = 0.0
        with tempfile.TemporaryDirectory(prefix="hf2l-verify-actual-models-") as temporary:
            root = Path(temporary)
            checkpoints = {}
            for record in records.values():
                folder = root / record.id
                store.download_snapshot(space_id, record.id, folder)
                document = _manifest(record, ROUND_FILE if record.kind == "model.global" else SUBMISSION_FILE)
                checkpoint = discover_checkpoint(folder)
                assert artifact_hashes(folder, checkpoint.artifact_paths) == document["checkpoint_files_sha256"]
                checkpoints[record.id] = load_file(str(folder / "model.safetensors"))
            for number in range(1, target_round + 1):
                global_model = checkpoints[rounds[number].id]
                document = _manifest(rounds[number], ROUND_FILE)
                updates_for_round = [checkpoints[item["resolved_revision"]] for item in document["submissions"]]
                for name, tensor in global_model.items():
                    expected = sum(update[name].astype(np.float64) * .5 for update in updates_for_round).astype(tensor.dtype)
                    difference = float(np.max(np.abs(tensor - expected)))
                    maximum = max(maximum, difference)
                    np.testing.assert_allclose(tensor, expected, rtol=1e-6, atol=1e-7)
        result.update(verified_downloaded_bytes=True, verified_fedavg_arithmetic=True,
                      maximum_fedavg_tensor_error=maximum)
    return result
