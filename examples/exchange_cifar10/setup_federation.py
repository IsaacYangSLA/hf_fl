"""Create the two-client FedAvg space and publish its initial VGG checkpoint."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import uuid

from common import run_hf2l, write_json_exclusive
from hf2l_exchange.auth import principal_id
from hf2l_exchange.client import ExchangeClient


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service-config", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--width-multiplier", type=float, default=0.25)
    parser.add_argument("--seed", type=int, default=20260923)
    args = parser.parse_args()
    if not 0 < args.width_multiplier <= 1:
        parser.error("width-multiplier must be in (0, 1]")
    config = json.loads(args.service_config.read_text())
    endpoint, issuer = config["endpoint"], config["issuer"]
    allow_http = config.get("allow_local_http", False)
    if type(allow_http) is not bool:
        parser.error("service-config allow_local_http must be a JSON boolean")
    identities = config["identities"]
    if set(identities) != {"owner", "client1", "client2"}:
        parser.error("service-config requires owner, client1 and client2 identities")
    subjects = [identities[name]["subject"] for name in ("owner", "client1", "client2")]
    if len(set(subjects)) != 3:
        parser.error("Owner and clients must have distinct subjects")
    token_path = Path(identities["owner"]["token_file"]).resolve(strict=True)
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    key = "cifar10-" + uuid.uuid4().hex
    with ExchangeClient(endpoint, lambda: token_path.read_text().strip(), allow_local_http=allow_http) as owner:
        space = owner.create_space("Two-client VGG CIFAR-10", profile="fedavg.v1", idempotency_key=key)
        write_json_exclusive(output / "setup.json", {"space_id": space.id, "idempotency_key": key})
        owner.register_type(space.id, "model.global", {"type": "object"},
                            publish_roles=["publisher"], visibility="shared", idempotency_key=key + "-global")
        owner.register_type(space.id, "training.update", {"type": "object"},
                            publish_roles=["contributor"], visibility="private", idempotency_key=key + "-update")
        for participant in ("client1", "client2"):
            subject = identities[participant]["subject"]
            owner.set_member(space.id, principal_id(issuer, subject), ["reader", "contributor"],
                             subject=subject, bindings={"participant": participant})
        run_hf2l("hf2l.init_repo", ["--backend", "exchange", "--repo-id", space.id,
                  "--plugin", "vgg-cifar10", "--plugin-arg", f"width_multiplier={args.width_multiplier}",
                  "--plugin-arg", f"seed={args.seed}"], token_file=token_path, endpoint=endpoint,
                  allow_local_http=allow_http)
        reference = owner.resolve(space.id, "main")
        descriptor = {"schema_version": 1, "endpoint": endpoint, "allow_local_http": allow_http,
                      "space_id": space.id, "base_revision": reference.record_id, "round_number": 1}
        write_json_exclusive(output / "round.json", descriptor)
    print(f"Space: {space.id}\nCommon immutable base: {reference.record_id}")
    print(f"Give BOTH clients the same round file: {output / 'round.json'}")


if __name__ == "__main__":
    main()
