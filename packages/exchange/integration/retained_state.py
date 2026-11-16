"""Native Go retained-state qualification through process restarts.

Python supplies only client requests and independent evidence checks. Every
service operation is performed by a native Go process; no Python server or
persistence implementation is imported.
"""
from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import hmac
import json
from pathlib import Path
import time
import traceback

import httpx
from hf2l_exchange.client_state import StateRepository
from hf2l_exchange.client_types import CoordinationHandle, ExchangeError
from hf2l_exchange.domain import principal_id
from hf2l_exchange.transfer_client import sha256

from go_fixture import GoFixture, load_json, private_json
from verify_go_sdk import assertion

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
def actor_client(fixture, client, subject):
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
    require(replay.id == sid, "space idempotency changed across restarts")
    require(client.register_type(sid, KIND, SCHEMA, idempotency_key=p + "-type").id == revision,
            "schema idempotency changed across restarts")
    with actor_client(fixture, client, ACTOR) as actor:
        record = actor.create_record(sid, kind=KIND, schema_revision_id=revision,
            metadata=metadata(p + "-0"), idempotency_key=p + "-record-0")
        require(record.id == manifest["records"][0], "record idempotency changed across restarts")
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
    require(replay.state == "completed", "completion replay lost across restarts")
    following = CoordinationHandle.from_dict(manifest["next_acquisition"])
    current = client.get_acquisition(sid, following.id)
    require(current.input_record_ids == following.input_record_ids and current.fence == following.fence,
            "second retained frozen acquisition changed")
    done = client.complete(sid, current, manifest["next_result"], idempotency_key=p + "-next-complete")
    require(done.state == "completed", "second retained completion failed")
    reference = client.resolve(sid, "continuation")
    require(reference.record_id == manifest["next_result"] and reference.token == "2",
            "second retained reference generation changed")
    require(client.get_record(sid, manifest["next_result"]).metadata["huge"] == HUGE, "retained large integer rounded")


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


def begin_partial(fixture, client, manifest, *, sdk_state):
    path = upload_data(fixture)
    sid = manifest["space"]
    attachment = {"path": "retained.bin", "size": path.stat().st_size, "sha256": sha256(path)}
    record = client.create_record(sid, kind=KIND, schema_revision_id=manifest["revision"],
        metadata=metadata("partial-native"), attachments=[attachment], idempotency_key="partial-native")
    blob = record.attachments[0]
    base = client.path(sid, client._record(record.id) + "/attachments/" + blob.id)
    started = client.request("POST", base + "/upload")
    require(started["state"] == "uploading", "native partial upload not ready")
    grant = client.request("POST", base + "/grants", body={"numbers": [1]})["grants"][0]
    part_size = started["part_size"]
    require(type(part_size) is int and part_size == int(fixture.env.get("EXCHANGE_PART_SIZE", PART_SIZE)),
            "native multipart descriptor differs from configured size")
    put_part(grant, path.read_bytes()[:part_size])
    result = {"path": path, "record": record.id, "attachment": blob.id, "attempt": started["attempt_id"],
              "sha256": attachment["sha256"], "part_size": part_size}
    if sdk_state:
        state_path = fixture.root / "retained-upload-state.json"
        repository = StateRepository(state_path)
        identity = [fixture.endpoint, sid, KIND, manifest["revision"], metadata("partial-native"), [attachment]]
        state = repository.begin("put_record", identity, idempotency_key="partial-native")
        state.update({"record_id": record.id, "publish_key": "partial-native-publish"})
        repository.save(state)
        result["state_path"] = state_path
    return result


def finish_partial(fixture, client, manifest, partial):
    sid, record_id, blob = manifest["space"], partial["record"], partial["attachment"]
    if "state_path" in partial:
        record = client.put_record(sid, kind=KIND, schema_revision_id=manifest["revision"],
            metadata=metadata("partial-native"), files={"retained.bin": partial["path"]},
            state_path=partial["state_path"], upload_seconds=120, verification_seconds=120)
    else:
        base = client.path(sid, client._record(record_id) + "/attachments/" + blob)
        present = client.request("GET", base + "/parts")["parts"]
        require(len(present) == 1 and present[0]["number"] == 1 and present[0]["size"] == partial["part_size"],
                "native restart did not recover provider multipart parts")
        grant = client.request("POST", base + "/grants", body={"numbers": [2]})["grants"][0]
        put_part(grant, partial["path"].read_bytes()[partial["part_size"]:])
        client.request("POST", base + "/complete")
        deadline = time.monotonic() + 120
        while True:
            record = client.get_record(sid, record_id)
            if record.attachments[0].state == "verified":
                break
            require(time.monotonic() < deadline, "native upload verification did not complete")
            time.sleep(.05)
        record = client.publish_record(sid, record_id, idempotency_key="partial-native-publish")
    require(record.id == record_id and record.state == "published", "native restart replaced retained record")
    output = fixture.root / "retained-download.bin"
    client.download_attachment(sid, record.id, record.attachments[0], output, seconds=120)
    require(sha256(output) == partial["sha256"], "resumed content differs")
    rows = fixture.query("SELECT id FROM v2_transfer_attempts WHERE blob_id=%s", (blob,))
    require(len(rows) == 1 and rows[0][0] == partial["attempt"], "native restart replaced retained upload attempt")


def receipt_payload(secret, receipt, authorization, thumb):
    """Verify the documented receipt envelope independently of service code."""
    encoded, signature = receipt.split(".")
    expected = hmac.new(secret.encode(), b"hf2l-exchange-gateway-put-v1\0" + encoded.encode("ascii"),
                        hashlib.sha256).hexdigest()
    require(hmac.compare_digest(signature, expected), "native receipt signature changed")
    payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    require(payload["version"] == 1, "native receipt version changed")
    require(payload["authorization_sha256"] == hashlib.sha256(authorization.encode()).hexdigest(),
            "native receipt authorization changed")
    require(payload["owner"]["certificate_thumbprint"] == thumb, "native receipt certificate changed")
    return payload


def workload_claims(fixture, space, grant, attempt, thumb, lifetime=4):
    now = int(time.time())
    return {"jti": grant, "grant_id": grant, "space_id": space, "job_id": "retained-job",
            "attempt_id": attempt, "component_id": "participant", "epoch": 1,
            "cnf": {"x5t#S256": thumb}, "iat": now, "exp": now + lifetime}


def settle_retained_receipts(fixture, receipts):
    while time.time() <= receipts["expires"]:
        time.sleep(.05)
    target = "/internal/transfers/v1/settle"
    def settle(receipt):
        authorization = receipts["authorization"]
        headers = assertion(fixture.backend_secret, "POST", target, authorization, receipts["thumb"])
        headers["Authorization"] = authorization
        with fixture.backend_http() as client:
            response = client.post(fixture.gateway_endpoint + target, json={"receipt": receipt}, headers=headers)
            require_http(response, 200, "native retained settlement receipt")
            return response.json()["settled"]
    first, second = receipts["receipts"]
    require(settle(first["value"]) is True, "native restart did not settle retained marker")
    require(settle(first["value"]) is False, "replay unexpectedly settled marker")
    rows = fixture.query("SELECT mutation_tokens FROM v2_transfer_attempts WHERE blob_id=%s",
                         (receipts["attachment"],))
    require(len(rows) == 1 and rows[0][0] == [second["token"]], "replay cleared successor marker")
    require(settle(second["value"]) is True, "native restart did not settle second marker")


class BackendAuth(httpx.Auth):
    def __init__(self, fixture, thumb):
        self.fixture, self.thumb = fixture, thumb

    def auth_flow(self, request):
        target = request.url.raw_path.decode("ascii")
        request.headers.update(assertion(self.fixture.backend_secret, request.method,
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
        headers = assertion(fixture.backend_secret, "POST", target, authorization, thumb)
        headers["Authorization"] = authorization
        with fixture.backend_http() as client:
            response = client.post(fixture.gateway_endpoint + target, json={}, headers=headers)
            require_http(response, 200, "native retained PUT receipt issue")
            result = response.json()
        item = {"value": result["receipt"], "origin_effect": "not_started"}
        values.append(item)
        private_json(receipt_path, retained)
        payload = receipt_payload(fixture.backend_secret, result["receipt"], authorization, thumb)
        item["token"] = payload["put"]["token"]
        private_json(receipt_path, retained)
        put_part(result["grant"], data)
        item["origin_effect"] = "closed_success"
        private_json(receipt_path, retained)
    owner.revoke_workload_grants(space.id, attempt_id="retained-go-attempt", idempotency_key="go-receipt-revoke")
    return retained


def run(config, report_path):
    root = report_path.parent
    fixtures = []
    report = {"status": "FAIL", "cases": {}, "stage": "setup"}
    def stage(value):
        report["stage"] = value
        private_json(root / "progress.json", {"stage": value})
    try:
        for name, sdk_state in (("sdk_resume", True), ("raw_resume", False)):
            stage(name + "_initialized")
            fixture = GoFixture(config, name=name, root=root / name)
            fixtures.append(fixture)
            fixture.setup()
            with fixture.client() as client:
                manifest = seed(fixture, client, name)
                partial = begin_partial(fixture, client, manifest, sdk_state=sdk_state)
                receipts = native_receipts(fixture, client)
            fixture.restart_services()
            stage(name + "_continued_after_restart")
            with fixture.client() as client:
                manifest = continue_state(fixture, client, manifest)
                finish_partial(fixture, client, manifest, partial)
                settle_retained_receipts(fixture, receipts)
            fixture.restart_services()
            stage(name + "_completed_after_second_restart")
            with fixture.client() as client:
                finish_state(client, manifest)
                record = client.get_record(manifest["space"], partial["record"])
                require(record.attachments[0].state == "verified", "retained verification state changed")
                output = fixture.root / "after-second-restart.bin"
                client.download_attachment(manifest["space"], record.id, record.attachments[0], output, seconds=120)
                require(sha256(output) == partial["sha256"], "retained download differs after second restart")
            report["cases"][name] = {"initialization": True, "idempotency": True,
                "large_integer": True, "unicode_principal": True, "coordination": True,
                "multipart_attempt_retained": True, "sealed_put_receipts": True,
                "native_process_restarts": 2}
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
        def cleanup(fixture):
            try:
                fixture.cleanup()
            except BaseException as error:
                return {"name": fixture.root.name, "error_class": type(error).__name__}
            return None
        # Default capabilities retain their full lifetime. Drain independently,
        # without rewriting expiry, mutation ownership, or accounting records.
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
