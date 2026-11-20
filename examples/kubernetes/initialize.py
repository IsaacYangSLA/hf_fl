"""One-time initial model publication, executed only inside Org P's cluster."""
from __future__ import annotations

import json
import os
from pathlib import Path

from hf2l.backends.factory import make_store
from hf2l.checkpoint.format import discover
from hf2l.core.protocol import AlgorithmSpec, RoundRecord
from hf2l.hub_helpers import ROUND_FILE, SCHEMA_VERSION, artifact_hashes, utc_now, write_json
from trainer import _model

_STATE_DIR = Path("/work/initialization")


def main() -> None:
    state = _STATE_DIR
    state.mkdir(parents=True, exist_ok=True)
    receipt = state / "published.json"
    if receipt.exists():
        raise RuntimeError("Initialization was already recorded; inspect the receipt before rerunning")
    if os.environ.get("EXCHANGE_TOKEN"):
        raise RuntimeError("Unset EXCHANGE_TOKEN so EXCHANGE_TOKEN_FILE remains renewable")
    if not Path(os.environ["EXCHANGE_TOKEN_FILE"]).is_file():
        raise RuntimeError("EXCHANGE_TOKEN_FILE must name an existing private token file")
    checkpoint = state / "initial-model"
    _model.initialize(checkpoint)
    store = make_store("exchange", endpoint=os.environ["EXCHANGE_ENDPOINT"])
    layout = discover(checkpoint)
    record = RoundRecord.from_dict({
        "schema_version": SCHEMA_VERSION,
        "backend": store.name,
        "round": 0,
        "algorithm": "initial model",
        "algorithm_spec": AlgorithmSpec("fedavg").to_dict(),
        "created_at": utc_now(),
        "checkpoint_files": list(layout.artifact_paths),
        "checkpoint_files_sha256": artifact_hashes(checkpoint, layout.artifact_paths),
        "initialization": {"source": "local_model_directory"},
        "submissions": [],
    }).to_dict()
    write_json(checkpoint / ROUND_FILE, record)
    result = store.initialize_repository(os.environ["HF2L_SPACE_ID"], checkpoint, private=True)
    payload = {"revision": result.revision}
    receipt.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload))


if __name__ == "__main__":
    main()
