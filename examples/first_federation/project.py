#!/usr/bin/env python3
"""Project administration for the first-federation example, using the public SDK.

Run through auth.py run. Identity receipts must come from the service
administrator's trusted Keycloak lookup; an invitation is never an identity proof.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import urlsplit
import uuid

from hf2l_exchange.client import ExchangeClient
from hf2l_exchange.client_types import ExchangeError
from hf2l_exchange.domain import principal_id

MODEL_AGREEMENT = {
    "algorithm": "fedavg",
    "checkpoint_format": "safetensors",
    "configuration": "match the immutable base config.json and complete tensor layout",
    "sample_count": "unique local training examples, not epoch visits",
    "minimum_participants": 2,
}


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, value):
    """Replace a private local state/descriptor atomically and durably."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Refusing a symlink output path")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + "-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def state_lock(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("Refusing a symlink state path")
    fd = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def https_url(value):
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Service endpoints and issuer must use HTTPS without credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("Service endpoints and issuer cannot contain query or fragment")
    return value.rstrip("/")


def identity(receipt, user):
    issuer = https_url(receipt["issuer"])
    accounts = receipt.get("accounts", receipt.get("users", {}))
    account = accounts[user]
    subject = account["subject"]
    if not isinstance(subject, str) or not subject or len(subject) > 256:
        raise ValueError("Trusted account receipt must contain its actual Keycloak subject")
    expected = principal_id(issuer, subject)
    if account.get("principal_id", expected) != expected:
        raise ValueError("Identity receipt principal does not match issuer and subject")
    return {"subject": subject, "principal_id": expected, "username": account.get("username", user)}


def create_project(client, state_path, *, name, receipt, owner, endpoint):
    """Retain the same operation key after any ambiguous network response."""
    endpoint = https_url(endpoint)
    owner_identity = identity(receipt, owner)
    intent = {"name": name, "endpoint": endpoint, "issuer": https_url(receipt["issuer"]),
              "client_id": receipt["client_id"], "owner": owner_identity}
    with state_lock(state_path):
        if Path(state_path).exists():
            state = read_json(state_path)
            if any(state.get(key) != value for key, value in intent.items()):
                raise ValueError("Existing setup intent differs; reuse its original arguments")
        else:
            state = {"schema_version": 1, **intent, "operation_key": "first-federation-" + uuid.uuid4().hex,
                     "participants": {}, "completed": False}
            write_json(state_path, state)
        if state["completed"]:
            space = client.get_space(state["space_id"])
            if space.profile != "fedavg.v1" or space.name != name:
                raise ValueError("Existing project no longer matches the saved setup")
            return state
        key = state["operation_key"]
        if "space_id" not in state:
            space = client.create_space(name, profile="fedavg.v1", idempotency_key=key)
            state["space_id"] = space.id
            write_json(state_path, state)
        sid = state["space_id"]
        client.register_type(sid, "model.global", {"type": "object"},
                             publish_roles=["publisher"], visibility="shared", idempotency_key=key + "-global")
        client.register_type(sid, "training.update", {"type": "object"},
                             publish_roles=["contributor"], visibility="private", idempotency_key=key + "-update")
        client.set_member(sid, owner_identity["principal_id"], ["admin", "publisher", "reader"],
                          subject=owner_identity["subject"])
        state["completed"] = True
        write_json(state_path, state)
        return state


def load_state(path, endpoint):
    state = read_json(path)
    if state.get("schema_version") != 1 or not state.get("completed") or not state.get("space_id"):
        raise ValueError("Complete administrator project creation before this command")
    if state["endpoint"] != https_url(endpoint):
        raise ValueError("Authenticated endpoint differs from the saved project")
    return state


def enroll(client, state_path, *, receipt, user, participant, endpoint):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", participant):
        raise ValueError("Participant must be a short name containing letters, digits, dot, dash or underscore")
    account = identity(receipt, user)
    with state_lock(state_path):
        state = load_state(state_path, endpoint)
        if https_url(receipt["issuer"]) != state["issuer"]:
            raise ValueError("Identity receipt issuer differs from the project issuer")
        if account["principal_id"] == state["owner"]["principal_id"]:
            raise ValueError("Project owner and training participant must use distinct accounts")
        for name, previous in state["participants"].items():
            if name == participant and previous != account:
                raise ValueError("Participant name is already assigned to another trusted identity")
            if name != participant and previous["principal_id"] == account["principal_id"]:
                raise ValueError("This identity already has a different participant binding")
        member = client.set_member(state["space_id"], account["principal_id"], ["reader", "contributor"],
                                   subject=account["subject"], bindings={"participant": participant})
        state["participants"][participant] = account
        write_json(state_path, state)
    return member.to_dict()


def invitation(client, state, *, participant, source_revision):
    if not re.fullmatch(r"[0-9a-f]{40}", source_revision):
        raise ValueError("Use the exact 40-character source commit used for all installations")
    account = state["participants"].get(participant)
    if account is None:
        raise ValueError("Enroll this participant before creating its invitation")
    current = next((m for m in client.members(state["space_id"]) if m.principal == account["principal_id"]), None)
    if current is None or not {"reader", "contributor"} <= set(current.roles) or current.bindings != {"participant": participant}:
        raise ValueError("Participant membership is missing, revoked or rebound")
    reference = client.resolve(state["space_id"], "main")
    record = client.get_record(state["space_id"], reference.record_id)
    if record.kind != "model.global" or record.state != "published":
        raise ValueError("The common base must be a published global model")
    document = record.metadata.get("hf2l_files", {}).get("fedavg_round.json", {})
    source_round = document.get("round")
    if type(source_round) is not int or source_round < 0:
        raise ValueError("Global model is missing its HF2L round manifest")
    return {"schema_version": 1, "endpoint": state["endpoint"], "issuer": state["issuer"],
            "client_id": state["client_id"], "space_id": state["space_id"], "participant": participant,
            "base_revision": reference.record_id, "source_round": source_round,
            "source_revision": source_revision, "model_agreement": dict(MODEL_AGREEMENT)}


def inspect_project(client, state):
    sid = state["space_id"]
    membership = client.get_membership(sid)
    result = {"endpoint": state["endpoint"], "space_id": sid, "membership": membership.to_dict()}
    try:
        reference = client.resolve(sid, "main")
    except ExchangeError as exc:
        if exc.status != 404:
            raise
        result["reference"] = None
        result["record"] = None
    else:
        result["reference"] = reference.to_dict()
        result["record"] = client.get_record(sid, reference.record_id).to_dict()
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create", help="Service administrator creates a recoverable project")
    create.add_argument("--state", type=Path, required=True)
    create.add_argument("--name", required=True)
    create.add_argument("--identities", type=Path, required=True, help="Trusted administrator Keycloak identity receipt")
    create.add_argument("--owner", default="owner")
    member = sub.add_parser("enroll", help="Project owner approves a trusted participant")
    member.add_argument("--state", type=Path, required=True)
    member.add_argument("--identities", type=Path, required=True)
    member.add_argument("--user", required=True)
    member.add_argument("--participant", required=True)
    invite = sub.add_parser("invite", help="Project owner writes a credential-free round invitation")
    invite.add_argument("--state", type=Path, required=True)
    invite.add_argument("--participant", required=True)
    invite.add_argument("--source-revision", required=True)
    invite.add_argument("--output", type=Path, required=True)
    inspect = sub.add_parser("inspect", help="Inspect own membership and the current global checkpoint")
    inspect.add_argument("--state", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if os.environ.get("EXCHANGE_TOKEN"):
            raise ValueError("Use auth.py run; EXCHANGE_TOKEN overrides token renewal")
        endpoint = https_url(os.environ["EXCHANGE_ENDPOINT"])
        token_path = Path(os.environ["EXCHANGE_TOKEN_FILE"])
        def token():
            value = token_path.read_text(encoding="utf-8").strip()
            if not value:
                raise ValueError("The managed access-token file is empty")
            return value
        with ExchangeClient(endpoint, token) as client:
            if args.command == "create":
                result = create_project(client, args.state, name=args.name, receipt=read_json(args.identities),
                                        owner=args.owner, endpoint=endpoint)
            elif args.command == "enroll":
                result = enroll(client, args.state, receipt=read_json(args.identities), user=args.user,
                                participant=args.participant, endpoint=endpoint)
            else:
                state = load_state(args.state, endpoint)
                if args.command == "invite":
                    result = invitation(client, state, participant=args.participant, source_revision=args.source_revision)
                    write_json(args.output, result)
                else:
                    result = inspect_project(client, state)
        print(json.dumps(result, sort_keys=True, allow_nan=False))
        return 0
    except (ValueError, KeyError, OSError, ExchangeError) as exc:
        parser.exit(1, f"project: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
