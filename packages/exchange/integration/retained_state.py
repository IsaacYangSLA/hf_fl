"""Bidirectional retained-state qualification; Python reference is a stopped-peer oracle.

The active server and worker are native Go. Each reference phase runs only while
all native processes for that fixture are stopped. This is not a Python bridge.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import traceback
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import httpx
from sqlalchemy import select
from hf2l_exchange import api
from hf2l_exchange.application import Service
from hf2l_exchange.auth import Authenticator, backend_assertion_headers
from hf2l_exchange.client_state import StateRepository
from hf2l_exchange.client_types import (CoordinationHandle, ExchangeError, MemberDescriptor,
    RecordDescriptor, ReferenceSnapshot, SpaceDescriptor, TypeRevision)
from hf2l_exchange.config import Settings
from hf2l_exchange.domain import Principal, principal_id
from hf2l_exchange.gateway_api import _open, _receipt_payload, _seal
from hf2l_exchange.migrations import check, initialize
from hf2l_exchange.models import TransferAttempt
from hf2l_exchange.storage import S3BlobStore
from hf2l_exchange.transfer_client import sha256
from hf2l_exchange.transfers import TransferService
from hf2l_exchange.worker import tick

from go_fixture import GoFixture, load_json, private_json

ACTOR = "opérator-雪"
HUGE = 2**100 + 12345
KIND = "retained.value"
SCHEMA = {"type": "object", "properties": {"huge": {"type": "integer"},
    "label": {"type": "string"}, "fraction": {"type": "number"}},
    "required": ["huge", "label", "fraction"], "additionalProperties": True}
SPACE_OPTIONS = {"quota_bytes": 64 * 1024**2, "principal_quota_bytes": 64 * 1024**2,
    "quota_records": 1000, "quota_metadata_bytes": 1024**2}
ROLES = ["reader", "contributor", "publisher"]
PART_SIZE = 8388608


def require(condition, label):
    if not condition:
        raise AssertionError(label)


def require_http(response, expected, label):
    if response.status_code == expected:
        return
    try:
        value = response.json()
        code = value.get("error", {}).get("code") if isinstance(value, dict) else None
    except (ValueError, TypeError):
        code = None
    raise ExchangeError(response.status_code, code if isinstance(code, str) else "unexpected_response",
                        {"stage": label})


@contextmanager
def configured(environment):
    previous = {key: os.environ.get(key) for key in environment if key.startswith("EXCHANGE_")}
    try:
        for key in previous:
            os.environ[key] = environment[key]
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class Reference:
    """Same application calls used by the reference HTTP boundary, without a server."""
    def __init__(self, fixture):
        with configured(fixture.env):
            self.settings = Settings.from_env(component="server")
        self.fixture = fixture
        self.service = Service(self.settings)
        self.transfers = TransferService(self.service, S3BlobStore(self.settings.storage))
        self.subject = fixture.owner_subject

    def principal(self, subject=None):
        subject = self.subject if subject is None else subject
        return Principal(principal_id(self.settings.auth.issuer, subject), subject,
                         subject == self.settings.auth.admin_subject)

    def close(self):
        self.service.engine.dispose()

    @contextmanager
    def actor(self, subject):
        prior = self.subject
        self.subject = subject
        try:
            yield self
        finally:
            self.subject = prior

    def create_space(self, name, *, profile="generic.v1", idempotency_key=None, **options):
        body = api.payload(api.SpaceBody(name=name, profile=profile, **options))
        return SpaceDescriptor.from_dict(self.service.create_space(self.principal(), body, idempotency_key))

    def register_type(self, space, kind, schema, *, idempotency_key=None):
        body = api.payload(api.TypeBody.model_validate({"schema": schema}))
        return TypeRevision.from_dict(self.service.register_type(self.principal(), space, kind, body, idempotency_key))

    def set_member(self, space, member, roles, *, subject=None, bindings=None):
        body = api.payload(api.MemberBody(roles=roles, subject=subject, bindings=bindings or {}))
        return MemberDescriptor.from_dict(self.service.put_member(self.principal(), space, member, body))

    def create_record(self, space, *, kind, schema_revision_id, metadata, attachments=(), idempotency_key=None):
        body = api.payload(api.RecordBody(kind=kind, schema_revision_id=schema_revision_id,
                                        metadata=metadata, attachments=list(attachments)))
        return RecordDescriptor.from_dict(self.service.create_record(self.principal(), space, body, idempotency_key))

    def publish_record(self, space, record, *, idempotency_key=None):
        return RecordDescriptor.from_dict(self.service.publish_record(self.principal(), space, record, idempotency_key))

    def get_record(self, space, record):
        return RecordDescriptor.from_dict(self.service.get_record(self.principal(), space, record))

    def set_ref(self, space, name, record_id, *, reference=None, idempotency_key=None):
        body = api.payload(api.ReferenceBody(record_id=record_id))
        expected = reference.token if reference is not None else "*"
        return ReferenceSnapshot.from_dict(self.service.put_reference(
            self.principal(), space, name, body, expected, idempotency_key))

    def resolve(self, space, name):
        return ReferenceSnapshot.from_dict(self.service.get_reference(self.principal(), space, name))

    def acquire(self, space, *, reference, input_ids=(), lease_seconds=3600, idempotency_key=None):
        body = api.payload(api.AcquisitionBody(reference=reference.name,
            expected_token=reference.token, input_record_ids=list(input_ids), lease_seconds=lease_seconds))
        return CoordinationHandle.from_dict(self.service.acquire(self.principal(), space, body, idempotency_key))

    def get_acquisition(self, space, acquisition_id):
        return CoordinationHandle.from_dict(self.service.get_acquisition(self.principal(), space, acquisition_id))

    def renew(self, space, handle):
        return CoordinationHandle.from_dict(self.service.renew(self.principal(), space, handle.id, handle.fence))

    def complete(self, space, handle, record_id, *, idempotency_key=None):
        body = api.payload(api.CompletionBody(fence=handle.fence, result_record_id=record_id))
        return CoordinationHandle.from_dict(self.service.complete(self.principal(), space, handle.id, body, idempotency_key))


@contextmanager
def actor_client(fixture, client, subject):
    if isinstance(client, Reference):
        with client.actor(subject) as value:
            yield value
    else:
        with fixture.client(subject) as value:
            yield value


def metadata(label):
    return {"huge": HUGE, "label": label, "fraction": 0.1, "one_float": 1.0,
            "negative_zero": -0.0, "unicode": "Straße/雪/σ", "nested": [False, None, {"n": HUGE + 1}]}


def expect_code(code, action):
    try:
        action()
    except Exception as error:
        require(getattr(error, "code", None) == code, "unexpected retained-state error code")
        return
    raise AssertionError("expected retained-state error was not raised")


def seed(fixture, client, prefix):
    space = client.create_space("Retained " + prefix, idempotency_key=prefix + "-space", **SPACE_OPTIONS)
    fixture.track_space(space.id)
    revision = client.register_type(space.id, KIND, SCHEMA, idempotency_key=prefix + "-type")
    client.set_member(space.id, fixture.principal(ACTOR), ROLES, subject=ACTOR)
    records = []
    with actor_client(fixture, client, ACTOR) as actor:
        for index in range(3):
            item = actor.create_record(space.id, kind=KIND, schema_revision_id=revision.id,
                metadata=metadata(prefix + "-" + str(index)), idempotency_key=prefix + "-record-" + str(index))
            item = actor.publish_record(space.id, item.id, idempotency_key=prefix + "-publish-" + str(index))
            records.append(item)
    reference = client.set_ref(space.id, "main", records[0].id, idempotency_key=prefix + "-ref")
    handle = client.acquire(space.id, reference=reference, input_ids=[records[2].id, records[1].id],
                           lease_seconds=3600, idempotency_key=prefix + "-acquire")
    require(set(handle.input_record_ids) == {records[1].id, records[2].id}, "seed frozen inputs")
    return {"prefix": prefix, "space": space.id, "revision": revision.id,
            "records": [item.id for item in records], "acquisition": handle.to_dict()}


def continue_state(fixture, client, manifest):
    p, sid, revision = manifest["prefix"], manifest["space"], manifest["revision"]
    replay = client.create_space("Retained " + p, idempotency_key=p + "-space", **SPACE_OPTIONS)
    require(replay.id == sid, "space idempotency changed across implementations")
    require(client.register_type(sid, KIND, SCHEMA, idempotency_key=p + "-type").id == revision,
            "schema idempotency changed across implementations")
    with actor_client(fixture, client, ACTOR) as actor:
        record = actor.create_record(sid, kind=KIND, schema_revision_id=revision,
            metadata=metadata(p + "-0"), idempotency_key=p + "-record-0")
        require(record.id == manifest["records"][0], "record idempotency changed across implementations")
        require(actor.get_record(sid, record.id).metadata["huge"] == HUGE, "large metadata integer rounded")
        require(record.creator == fixture.principal(ACTOR), "Unicode principal changed")
        expect_code("idempotency_conflict", lambda: actor.create_record(sid, kind=KIND,
            schema_revision_id=revision, metadata=metadata("different"), idempotency_key=p + "-record-0"))
    old = CoordinationHandle.from_dict(manifest["acquisition"])
    current = client.get_acquisition(sid, old.id)
    require(current.fence == old.fence and current.input_record_ids == old.input_record_ids,
            "retained acquisition fence or frozen inputs changed")
    renewed = client.renew(sid, current)
    require(renewed.fence == old.fence, "renew changed fence")
    result = client.create_record(sid, kind=KIND, schema_revision_id=revision,
        metadata=metadata(p + "-result"), idempotency_key=p + "-result")
    result = client.publish_record(sid, result.id, idempotency_key=p + "-result-publish")
    completed = client.complete(sid, renewed, result.id, idempotency_key=p + "-complete")
    require(completed.state == "completed", "retained acquisition did not complete")
    require(client.resolve(sid, "main").record_id == result.id, "retained completion reference mismatch")
    branch = client.set_ref(sid, "continuation", result.id, idempotency_key=p + "-continuation-ref")
    next_handle = client.acquire(sid, reference=branch, input_ids=old.input_record_ids,
        lease_seconds=3600, idempotency_key=p + "-continuation-acquire")
    next_result = client.create_record(sid, kind=KIND, schema_revision_id=revision,
        metadata=metadata(p + "-next-result"), idempotency_key=p + "-next-result")
    next_result = client.publish_record(sid, next_result.id, idempotency_key=p + "-next-result-publish")
    manifest.update({"result": result.id, "next_result": next_result.id,
                     "next_acquisition": next_handle.to_dict()})
    return manifest


def finish_state(client, manifest):
    sid, p = manifest["space"], manifest["prefix"]
    first = CoordinationHandle.from_dict(manifest["acquisition"])
    replay = client.complete(sid, first, manifest["result"], idempotency_key=p + "-complete")
    require(replay.state == "completed", "completion replay lost across implementations")
    following = CoordinationHandle.from_dict(manifest["next_acquisition"])
    current = client.get_acquisition(sid, following.id)
    require(current.input_record_ids == following.input_record_ids and current.fence == following.fence,
            "second retained frozen acquisition changed")
    done = client.complete(sid, current, manifest["next_result"], idempotency_key=p + "-next-complete")
    require(done.state == "completed", "second retained completion failed")
    reference = client.resolve(sid, "continuation")
    require(reference.record_id == manifest["next_result"] and reference.token == "2",
            "second retained reference generation changed")
    require(client.get_record(sid, manifest["next_result"]).metadata["huge"] == HUGE, "reverse large integer rounded")


def upload_data(fixture):
    part_size = int(fixture.env.get("EXCHANGE_PART_SIZE", PART_SIZE))
    require(5242880 <= part_size <= 16 * 1024**2, "fixture multipart size is not bounded")
    path = fixture.root / "retained-multipart.bin"
    pattern = bytes(range(256))
    path.write_bytes(pattern * (part_size // 256) + pattern[:part_size % 256] + b"retained-final-part")
    return path


def put_part(grant, data):
    with httpx.Client(trust_env=False, timeout=60) as client:
        response = client.put(grant["url"], content=data, headers=grant.get("headers", {}))
        require(response.status_code in (200, 201, 204), "retained provider PUT did not complete")
        # Closing the response is the proof that this fixture's exact provider operation ended.
        response.close()


def begin_partial_reference(fixture, reference, manifest):
    path = upload_data(fixture)
    sid = manifest["space"]
    attachment = {"path": "retained.bin", "size": path.stat().st_size, "sha256": sha256(path)}
    record = reference.create_record(sid, kind=KIND, schema_revision_id=manifest["revision"],
        metadata=metadata("partial-python"), attachments=[attachment], idempotency_key="partial-python")
    blob = record.attachments[0]
    started = reference.transfers.initiate(sid, record.id, blob.id, reference.principal())
    require(started["state"] == "uploading", "reference partial upload not ready")
    grant = reference.transfers.grants(sid, record.id, blob.id, reference.principal(), [1])["grants"][0]
    part_size = started["part_size"]
    require(type(part_size) is int and part_size == int(fixture.env.get("EXCHANGE_PART_SIZE", PART_SIZE)),
            "reference multipart descriptor differs from configured size")
    put_part(grant, path.read_bytes()[:part_size])
    state_path = fixture.root / "retained-upload-state.json"
    repository = StateRepository(state_path)
    identity = [fixture.endpoint, sid, KIND, manifest["revision"], metadata("partial-python"), [attachment]]
    state = repository.begin("put_record", identity, idempotency_key="partial-python")
    state.update({"record_id": record.id, "publish_key": "partial-python-publish"})
    repository.save(state)
    return {"path": path, "state_path": state_path, "record": record.id, "attachment": blob.id,
            "attempt": started["attempt_id"], "sha256": attachment["sha256"], "part_size": part_size}


def finish_partial_go(fixture, client, manifest, partial):
    record = client.put_record(manifest["space"], kind=KIND, schema_revision_id=manifest["revision"],
        metadata=metadata("partial-python"), files={"retained.bin": partial["path"]},
        state_path=partial["state_path"], upload_seconds=120, verification_seconds=120)
    require(record.id == partial["record"] and record.state == "published", "Go did not resume reference record")
    attachment = record.attachments[0]
    output = fixture.root / "python-to-go-download.bin"
    client.download_attachment(manifest["space"], record.id, attachment, output, seconds=120)
    require(sha256(output) == partial["sha256"], "Go resumed content differs")
    rows = fixture.query("SELECT id FROM v2_transfer_attempts WHERE blob_id=%s", (partial["attachment"],))
    require(len(rows) == 1 and rows[0][0] == partial["attempt"], "Go replaced the retained upload attempt")


def begin_partial_go(fixture, client, manifest):
    path = upload_data(fixture)
    sid = manifest["space"]
    record = client.create_record(sid, kind=KIND, schema_revision_id=manifest["revision"],
        metadata=metadata("partial-go"), attachments=[{"path": "retained.bin", "size": path.stat().st_size,
        "sha256": sha256(path)}], idempotency_key="partial-go")
    blob = record.attachments[0]
    base = client.path(sid, client._record(record.id) + "/attachments/" + blob.id)
    started = client.request("POST", base + "/upload")
    require(started["state"] == "uploading", "Go partial upload not ready")
    grant = client.request("POST", base + "/grants", body={"numbers": [1]})["grants"][0]
    part_size = started["part_size"]
    require(type(part_size) is int and part_size == int(fixture.env.get("EXCHANGE_PART_SIZE", PART_SIZE)),
            "native multipart descriptor differs from configured size")
    put_part(grant, path.read_bytes()[:part_size])
    return {"path": path, "record": record.id, "attachment": blob.id, "attempt": started["attempt_id"],
            "sha256": sha256(path), "part_size": part_size}


def finish_partial_reference(reference, manifest, partial):
    sid, record, blob = manifest["space"], partial["record"], partial["attachment"]
    present = reference.transfers.parts(sid, record, blob, reference.principal())["parts"]
    require(len(present) == 1 and present[0]["number"] == 1 and present[0]["size"] == partial["part_size"],
            "reference did not recover Go multipart parts")
    grant = reference.transfers.grants(sid, record, blob, reference.principal(), [2])["grants"][0]
    put_part(grant, partial["path"].read_bytes()[partial["part_size"]:])
    reference.transfers.complete(sid, record, blob, reference.principal())
    deadline = time.monotonic() + 120
    while True:
        tick(reference.transfers)
        state = reference.get_record(sid, record)
        if state.attachments[0].state == "verified":
            break
        require(time.monotonic() < deadline, "reference verification did not complete")
        time.sleep(.05)
    published = reference.publish_record(sid, record, idempotency_key="partial-go-publish")
    require(published.state == "published", "reference did not publish Go upload")


def workload_claims(fixture, space, grant, attempt, thumb, lifetime=4):
    now = int(time.time())
    return {"jti": grant, "grant_id": grant, "space_id": space, "job_id": "retained-job",
            "attempt_id": attempt, "component_id": "participant", "epoch": 1,
            "cnf": {"x5t#S256": thumb}, "iat": now, "exp": now + lifetime}


def reference_receipts(fixture, reference):
    owner = reference.principal()
    space = reference.create_space("Retained Python receipt", idempotency_key="python-receipt-space", **SPACE_OPTIONS)
    fixture.track_space(space.id)
    revision = reference.register_type(space.id, KIND, SCHEMA, idempotency_key="python-receipt-type")
    reference.service.enable_managed_space(owner, space.id, {"job_id": "retained-job"}, "python-managed")
    subject = "retained-workload-python-雪"
    pid = principal_id(fixture.workload_issuer, subject)
    thumb = hashlib.sha256(b"retained-python-certificate").digest()
    import base64
    thumb = base64.urlsafe_b64encode(thumb).rstrip(b"=").decode()
    reference.service.put_member(owner, space.id, pid, {"subject": subject, "roles": ROLES, "bindings": {}})
    grant = reference.service.create_workload_grant(owner, space.id, {"subject": subject,
        "job_id": "retained-job", "attempt_id": "retained-python-attempt", "component_id": "participant",
        "epoch": 1, "expires_at": time.time() + 3600, "certificate_thumbprint": thumb,
        "roles": ROLES, "bindings": {}}, "python-workload-grant")
    claims = workload_claims(fixture, space.id, grant["grant_id"], "retained-python-attempt", thumb)
    token = fixture.workload_token(subject, claims, audience="hf2l-transfer", scope="transfer")
    authorization = "Bearer " + token
    auth = Authenticator(replace(reference.settings.auth, workload_audience="hf2l-transfer"))
    principal = auth.authenticate(authorization, managed=True, certificate_thumbprint=thumb)
    data = b"retained Python receipt"
    record = reference.service.create_record(principal, space.id, {
        "kind": KIND, "schema_revision_id": revision.id, "metadata": metadata("receipt-python"),
        "attachments": [{"path": "receipt.bin", "size": len(data),
                         "sha256": hashlib.sha256(data).hexdigest()}]}, "python-receipt-record")
    blob = record["attachments"][0]["id"]
    reference.transfers.initiate(space.id, record["id"], blob, principal)
    receipts = []
    retained = {"authorization": authorization, "thumb": thumb, "expires": claims["exp"],
                "receipts": receipts, "attachment": blob, "space": space.id}
    receipt_path = fixture.root / "python-issued-put-receipts.json"
    for _ in range(2):
        handle, origin = reference.transfers.begin_gateway_put(principal, space.id, record["id"], blob, 1)
        item = {"value": _seal(fixture.backend_secret, _receipt_payload(principal, authorization, handle)),
                "token": handle.token, "origin_effect": "not_started"}
        receipts.append(item)
        private_json(receipt_path, retained)
        put_part(origin, data)
        item["origin_effect"] = "closed_success"
        private_json(receipt_path, retained)
    reference.service.revoke_workload_grants(owner, space.id,
        {"attempt_id": "retained-python-attempt"}, "python-receipt-revoke")
    return retained


def settle_python_receipts_go(fixture, receipts):
    while time.time() <= receipts["expires"]:
        time.sleep(.05)
    target = "/internal/transfers/v1/settle"
    def settle(receipt):
        authorization = receipts["authorization"]
        headers = backend_assertion_headers(fixture.backend_secret, "POST", target, authorization, receipts["thumb"])
        headers["Authorization"] = authorization
        with fixture.backend_http() as client:
            response = client.post(fixture.gateway_endpoint + target, json={"receipt": receipt}, headers=headers)
            require_http(response, 200, "Go retained Python settlement receipt")
            return response.json()["settled"]
    first, second = receipts["receipts"]
    require(settle(first["value"]) is True, "Go did not settle Python marker")
    require(settle(first["value"]) is False, "Go replay unexpectedly settled marker")
    rows = fixture.query("SELECT mutation_tokens FROM v2_transfer_attempts WHERE blob_id=%s",
                         (receipts["attachment"],))
    require(len(rows) == 1 and rows[0][0] == [second["token"]], "Go replay cleared successor marker")
    require(settle(second["value"]) is True, "Go did not settle second Python marker")


class BackendAuth(httpx.Auth):
    def __init__(self, fixture, thumb):
        self.fixture, self.thumb = fixture, thumb

    def auth_flow(self, request):
        target = request.url.raw_path.decode("ascii")
        request.headers.update(backend_assertion_headers(self.fixture.backend_secret, request.method,
            target, request.headers.get("authorization", ""), self.thumb))
        yield request


def native_receipts(fixture, owner):
    from hf2l_exchange.client import ExchangeClient
    import base64
    space = owner.create_space("Retained Go receipt", idempotency_key="go-receipt-space", **SPACE_OPTIONS)
    fixture.track_space(space.id)
    revision = owner.register_type(space.id, KIND, SCHEMA, idempotency_key="go-receipt-type")
    owner.manage_space(space.id, job_id="retained-job", idempotency_key="go-managed")
    subject = "retained-workload-go-雪"
    pid = principal_id(fixture.workload_issuer, subject)
    thumb = base64.urlsafe_b64encode(hashlib.sha256(b"retained-go-certificate").digest()).rstrip(b"=").decode()
    owner.set_member(space.id, pid, ROLES, subject=subject)
    grant = owner.create_workload_grant(space.id, subject=subject, job_id="retained-job",
        attempt_id="retained-go-attempt", component_id="participant", epoch=1,
        expires_at=time.time() + 3600, certificate_thumbprint=thumb, roles=ROLES,
        idempotency_key="go-workload-grant")
    claims = workload_claims(fixture, space.id, grant.grant_id, "retained-go-attempt", thumb, lifetime=120)
    control_token = fixture.workload_token(subject, claims)
    data = b"retained Go receipt"
    with fixture.backend_http() as control_http:
        control_http.auth = BackendAuth(fixture, thumb)
        with ExchangeClient(fixture.managed_endpoint, control_token, http=control_http,
                            allow_local_http=True, retries=1) as workload:
            record = workload.create_record(space.id, kind=KIND, schema_revision_id=revision.id,
                metadata=metadata("receipt-go"), attachments=[{"path": "receipt.bin", "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest()}], idempotency_key="go-receipt-record")
            blob = record.attachments[0].id
            base = workload.path(space.id, workload._record(record.id) + "/attachments/" + blob)
            workload.request("POST", base + "/upload")
    claims.update({"iat": int(time.time()), "exp": int(time.time()) + 4})
    authorization = "Bearer " + fixture.workload_token(subject, claims, audience="hf2l-transfer", scope="transfer")
    target = ("/internal/transfers/v1/spaces/" + space.id + "/records/" + record.id +
              "/attachments/" + blob + "/parts/1/begin")
    values = []
    retained = {"authorization": authorization, "thumb": thumb, "expires": claims["exp"],
                "receipts": values, "attachment": blob, "space": space.id}
    receipt_path = fixture.root / "go-issued-put-receipts.json"
    for _ in range(2):
        headers = backend_assertion_headers(fixture.backend_secret, "POST", target, authorization, thumb)
        headers["Authorization"] = authorization
        with fixture.backend_http() as client:
            response = client.post(fixture.gateway_endpoint + target, json={}, headers=headers)
            require_http(response, 200, "native retained PUT receipt issue")
            result = response.json()
        item = {"value": result["receipt"], "origin_effect": "not_started"}
        values.append(item)
        private_json(receipt_path, retained)
        handle = _open(fixture.backend_secret, result["receipt"], authorization, thumb)
        item["token"] = handle.token
        private_json(receipt_path, retained)
        put_part(result["grant"], data)
        item["origin_effect"] = "closed_success"
        private_json(receipt_path, retained)
    owner.revoke_workload_grants(space.id, attempt_id="retained-go-attempt", idempotency_key="go-receipt-revoke")
    return retained


def settle_go_receipts_reference(fixture, reference, receipts):
    while time.time() <= receipts["expires"]:
        time.sleep(.05)
    handles = [_open(fixture.backend_secret, item["value"], receipts["authorization"], receipts["thumb"])
               for item in receipts["receipts"]]
    require(reference.transfers.finish_gateway_put(handles[0]) is True, "Python rejected native receipt marker")
    require(reference.transfers.finish_gateway_put(handles[0]) is False, "Python replay settled a successor")
    with reference.service.sessions.begin() as session:
        rows = list(session.scalars(select(TransferAttempt).where(TransferAttempt.blob_id == receipts["attachment"])))
        require(len(rows) == 1 and rows[0].mutation_tokens == [handles[1].token],
                "Python replay changed successor marker")
    require(reference.transfers.finish_gateway_put(handles[1]) is True, "Python did not settle second native marker")


def run(config, report_path):
    root = report_path.parent
    fixtures = []
    report = {"status": "FAIL", "cases": {}, "stage": "setup"}
    def stage(value):
        report["stage"] = value
        private_json(root / "progress.json", {"stage": value})
    try:
        stage("python_initialized")
        first = GoFixture(config, name="retained-python", root=root / "python-first")
        fixtures.append(first)
        first.setup(initialize=False, start=False)
        reference = Reference(first)
        try:
            initialize(reference.service.engine)
            seeded = seed(first, reference, "python-first")
            partial = begin_partial_reference(first, reference, seeded)
            python_receipts = reference_receipts(first, reference)
        finally:
            reference.close()
        first.start_services()
        stage("go_continues_python")
        with first.client() as client:
            seeded = continue_state(first, client, seeded)
            finish_partial_go(first, client, seeded, partial)
            settle_python_receipts_go(first, python_receipts)
        first.stop_services()
        reference = Reference(first)
        try:
            check(reference.service.engine)
            finish_state(reference, seeded)
            require(reference.get_record(seeded["space"], partial["record"]).attachments[0].state == "verified",
                    "Python cannot read Go-verified retained blob")
        finally:
            reference.close()
        first.start_services()
        with first.client() as client:
            require(client.resolve(seeded["space"], "continuation").token == "2", "Go cannot read Python completion")
        report["cases"]["python_to_go"] = {"initialization": True, "idempotency": True,
            "large_integer": True, "unicode_principal": True, "coordination": True,
            "multipart_attempt_retained": True, "sealed_put_receipts": True}

        stage("go_initialized")
        second = GoFixture(config, name="retained-go", root=root / "go-first")
        fixtures.append(second)
        second.setup()
        with second.client() as client:
            native = seed(second, client, "go-first")
            partial_go = begin_partial_go(second, client, native)
            go_receipts = native_receipts(second, client)
        second.stop_services()
        stage("python_continues_go")
        reference = Reference(second)
        try:
            check(reference.service.engine)
            native = continue_state(second, reference, native)
            finish_partial_reference(reference, native, partial_go)
            settle_go_receipts_reference(second, reference, go_receipts)
        finally:
            reference.close()
        second.start_services()
        with second.client() as client:
            finish_state(client, native)
            record = client.get_record(native["space"], partial_go["record"])
            output = second.root / "go-to-python-download.bin"
            client.download_attachment(native["space"], record.id, record.attachments[0], output, seconds=120)
            require(sha256(output) == partial_go["sha256"], "Go cannot download Python-verified native upload")
        report["cases"]["go_to_python"] = {"initialization": True, "idempotency": True,
            "large_integer": True, "unicode_principal": True, "coordination": True,
            "multipart_attempt_retained": True, "sealed_put_receipts": True}
        stage("capability_drain_and_cleanup")
    except BaseException as error:
        report["error_class"] = type(error).__name__
        if isinstance(getattr(error, "code", None), str):
            report["error_code"] = error.code
            report["error_status"] = getattr(error, "status", None)
        private_json(root / "failure.json", {key: report[key] for key in
            ("stage", "error_class", "error_code", "error_status") if key in report})
        traceback.print_exc()
    finally:
        cleanup_errors = []
        def cleanup(fixture):
            try:
                fixture.cleanup()
            except BaseException as error:
                return {"name": fixture.root.name, "error_class": type(error).__name__}
            return None
        # Default signed capabilities retain their full lifetime. Independent
        # fixtures drain concurrently; no expiry or accounting state is rewritten.
        with ThreadPoolExecutor(max_workers=max(1, len(fixtures))) as pool:
            cleanup_errors = [value for value in pool.map(cleanup, fixtures) if value is not None]
        report["cleanup_errors"] = cleanup_errors
        if len(report["cases"]) == 2 and not cleanup_errors and "error_class" not in report:
            report["status"] = "PASS"
            report["stage"] = "complete"
        private_json(report_path, report)
    return 0 if report["status"] == "PASS" else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    report = Path(args.report).resolve()
    report.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    report.parent.chmod(0o700)
    return run(load_json(args.config), report)


if __name__ == "__main__":
    raise SystemExit(main())
