"""Unmodified Python SDK acceptance against native Go Exchange and real storage."""
from __future__ import annotations
import argparse
import base64
from dataclasses import replace
import hashlib
import hmac
import inspect
import json
from pathlib import Path
import ssl
import sys
import time
import traceback
import uuid

import httpx

from hf2l_exchange.client import ExchangeClient
from hf2l_exchange.client_types import ExchangeError
from hf2l_exchange.transfer_client import TransferManager
from go_fixture import GoFixture, load_json, private_json


def assert_error(action, status, code=None):
    try:
        action()
    except ExchangeError as exc:
        assert exc.status == status, (exc.status, status, exc.code)
        if code is not None:
            assert exc.code == code, (exc.code, code)
        return exc
    raise AssertionError("expected_exchange_error")


def assertion(secret, method, target, authorization, thumbprint):
    stamp = str(int(time.time()))
    body = json.dumps([method.upper(), target, authorization, thumbprint, stamp],
                      separators=(",", ":")).encode()
    return {"Authorization": authorization, "X-HF2L-Backend-Timestamp": stamp,
            "X-HF2L-TLS-Thumbprint": thumbprint,
            "X-HF2L-Backend-Signature": hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()}


def run(config):
    fixture = GoFixture(config)
    report = {"status": "FAIL", "checks": [], "implementation": "native Go Exchange"}
    started = time.monotonic()

    def checked(name, **facts):
        report["checks"].append({"name": name, **facts})
        private_json(fixture.root / "progress.json", {
            "stage": name, "passed_checks": len(report["checks"])})

    sdk_paths = [Path(inspect.getfile(ExchangeClient)), Path(inspect.getfile(TransferManager))]
    sdk_before = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sdk_paths}
    report["python_sdk_source_sha256"] = sdk_before
    report["native_binary_sha256"] = fixture.binary_hash
    sources = [Path(__file__), Path(__file__).with_name("go_fixture.py"), *sdk_paths]
    report["harness_sha256"] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in sources}
    evidence = fixture.root / "source-evidence"
    evidence.mkdir(mode=0o700)
    for path in sources:
        (evidence / path.name).write_bytes(path.read_bytes())
    failure = None
    try:
        fixture.setup()
        owner, alice, bob, foreign = (fixture.client(subject) for subject in ("owner", "alice", "bob", "foreign"))
        assert_error(lambda: foreign.create_space("Forbidden bootstrap"), 403, "bootstrap_admin_required")
        space = owner.create_space("Native SDK generic", idempotency_key="generic-create",
            quota_bytes=64 * 1024 * 1024, principal_quota_bytes=32 * 1024 * 1024)
        fixture.track_space(space.id)
        repeated = owner.create_space("Native SDK generic", idempotency_key="generic-create",
            quota_bytes=64 * 1024 * 1024, principal_quota_bytes=32 * 1024 * 1024)
        assert repeated.id == space.id
        assert_error(lambda: owner.create_space("Changed name", idempotency_key="generic-create"), 409,
                     "idempotency_conflict")
        for subject in ("alice", "bob"):
            member = owner.set_member(space.id, fixture.principal(subject), ["reader", "contributor"],
                                      subject=subject, bindings={"organization": subject})
            assert set(member.roles) == {"reader", "contributor"}
        assert_error(lambda: foreign.get_space(space.id), 404, "space_not_found")
        checked("space_bootstrap_membership_idempotency")

        schema = {"type": "object", "$defs": {"count": {"type": "integer", "minimum": 0}},
                  "properties": {"name": {"type": "string"}, "count": {"$ref": "#/$defs/count"}},
                  "required": ["name", "count"], "additionalProperties": False}
        revision = owner.register_type(space.id, "generic.bundle", schema,
                                       publish_roles=["contributor", "publisher"], visibility="shared")
        expected_digest = hashlib.sha256(json.dumps(schema, ensure_ascii=False, sort_keys=True,
                                                   separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        assert revision.digest == expected_digest
        assert owner.get_type(space.id, revision.kind, revision.revision).id == revision.id
        assert any(item.id == revision.id for item in owner.types(space.id))
        assert_error(lambda: alice.create_record(space.id, kind=revision.kind, schema_revision_id=revision.id,
            metadata={"name": "wrong", "count": True}), 422, "metadata_schema_mismatch")
        huge = 2 ** 80
        draft = alice.create_record(space.id, kind=revision.kind, schema_revision_id=revision.id,
            metadata={"name": "naïve", "count": huge}, idempotency_key="draft-replay")
        replay = alice.create_record(space.id, kind=revision.kind, schema_revision_id=revision.id,
            metadata={"name": "naïve", "count": huge}, idempotency_key="draft-replay")
        assert draft.id == replay.id and draft.metadata["count"] == huge
        changed = alice.update_record(space.id, draft.id, metadata={"name": "updated", "count": huge + 1},
                                      version=draft.version)
        assert changed.version == draft.version + 1
        assert_error(lambda: alice.update_record(space.id, draft.id, metadata={"name": "stale", "count": 1},
                                                version=draft.version), 412, "record_version_mismatch")
        checked("full_schema_canonical_digest_huge_integer_draft_cas")

        context = ssl.create_default_context(cafile=str(fixture.server_ca))
        with httpx.Client(verify=context, trust_env=False, timeout=10) as raw:
            bad = raw.post(fixture.endpoint + "/v2/spaces",
                headers={"Authorization": "Bearer " + fixture.token(), "Idempotency-Key": "bad-shape"},
                json={"name": "bad", "unexpected": True})
            assert bad.status_code == 422 and isinstance(bad.json()["error"]["code"], str)
            no_auth = raw.get(fixture.endpoint + "/v2/spaces/" + space.id)
            assert no_auth.status_code == 401 and "Bearer" in no_auth.headers.get("WWW-Authenticate", "")
            missing_cas = raw.patch(fixture.endpoint + "/v2/spaces/" + space.id + "/records/" + draft.id,
                headers={"Authorization": "Bearer " + fixture.token("alice")},
                json={"metadata": {"name": "missing precondition", "count": 1}})
            assert missing_cas.status_code == 428
            assert no_auth.json()["error"].get("request_id")
        checked("strict_http_error_and_precondition_contract")

        files = fixture.root / "inputs"
        files.mkdir()
        empty = files / "empty.bin"
        empty.write_bytes(b"")
        payload = files / "model.bin"
        # Deterministic opaque bytes; Exchange must not deserialize or execute them.
        payload.write_bytes((bytes(range(256)) * (5 * 1024 * 1024 // 256)) + b"native-go-sdk-tail")
        bundle = alice.put_record(space.id, kind=revision.kind, schema_revision_id=revision.id,
            metadata={"name": "multipart", "count": 2},
            files={"empty.bin": empty, "nested/model.bin": payload},
            state_path=fixture.root / "bundle-state.json", upload_seconds=120, verification_seconds=120)
        assert bundle.state == "published" and len(bundle.attachments) == 2
        for attachment in bundle.attachments:
            destination = fixture.root / "downloads" / attachment.path
            bob.download_attachment(space.id, bundle.id, attachment, destination, seconds=90)
            original = empty if attachment.path == "empty.bin" else payload
            assert destination.read_bytes() == original.read_bytes()
            assert destination.stat().st_size == attachment.size
            assert hashlib.sha256(destination.read_bytes()).hexdigest() == attachment.sha256
        assert_error(lambda: alice.update_record(space.id, bundle.id,
            metadata={"name": "immutable", "count": 0}, version=bundle.version), 409, "record_not_draft")
        checked("sdk_zero_byte_multipart_publish_versioned_download", bytes=payload.stat().st_size,
                attachments=2, download_hashes_verified=True)

        published = [bundle.id]
        for index in range(3):
            record = alice.put_record(space.id, kind=revision.kind, schema_revision_id=revision.id,
                metadata={"name": "page-" + str(index), "count": index}, files={},
                state_path=fixture.root / ("metadata-state-" + str(index) + ".json"))
            published.append(record.id)
        page_records = list(bob.records(space.id, kind=revision.kind, limit=1))
        assert {record.id for record in page_records} == set(published)
        events, cursor = bob.events(space.id, limit=100)
        assert events and cursor
        private_type = owner.register_type(space.id, "private.note", {"type": "object"},
                                           publish_roles=["contributor"], visibility="private")
        _, cursor = bob.events(space.id, limit=100)
        note = alice.create_record(space.id, kind=private_type.kind, schema_revision_id=private_type.id,
                                   metadata={"private": True})
        assert_error(lambda: bob.get_record(space.id, note.id), 404, "record_not_found")
        hidden, after_hidden = bob.events(space.id, cursor=cursor, limit=1)
        assert hidden == () and after_hidden > cursor
        owner.set_member(space.id, fixture.principal("bob"), [], subject="bob")
        assert_error(lambda: bob.get_record(space.id, bundle.id), 404, "space_not_found")
        owner.set_member(space.id, fixture.principal("bob"), ["reader", "contributor"], subject="bob",
                         bindings={"organization": "bob"})
        alice.cancel_record(space.id, draft.id)
        owner.purge_record(space.id, draft.id)
        assert_error(lambda: owner.get_record(space.id, draft.id), 404, "record_not_found")
        checked("sdk_pagination_event_visibility_revocation_and_explicit_purge")

        quota = owner.create_space("Bounded quota", quota_bytes=1, principal_quota_bytes=1)
        fixture.track_space(quota.id)
        qt = owner.register_type(quota.id, "opaque", {"type": "object"})
        assert_error(lambda: owner.create_record(quota.id, kind="opaque", schema_revision_id=qt.id, metadata={},
            attachments=[{"path": "too-large", "size": 2, "sha256": hashlib.sha256(b"xx").hexdigest()}]),
            409, "blob_quota_exceeded")
        checked("reservation_quota_refusal")

        fed = owner.create_space("Two-organization provenance", profile="fedavg.v1")
        fixture.track_space(fed.id)
        for subject in ("alice", "bob"):
            owner.set_member(fed.id, fixture.principal(subject), ["reader", "contributor"],
                             subject=subject, bindings={"participant": subject})
        globals_type = owner.register_type(fed.id, "model.global", {"type": "object"})
        updates_type = owner.register_type(fed.id, "training.update", {"type": "object"})
        initial = owner.put_record(fed.id, kind="model.global", schema_revision_id=globals_type.id,
                                   metadata={"inputs": []}, files={})
        reference = owner.set_ref(fed.id, "main", initial.id)
        updates = []
        for client, subject, count in ((alice, "alice", 16), (bob, "bob", 24)):
            update = client.put_record(fed.id, kind="training.update", schema_revision_id=updates_type.id,
                metadata={"base_record_id": initial.id, "sample_count": count}, files={})
            assert update.creator_bindings["participant"] == subject
            updates.append(update.id)
        handle = owner.acquire(fed.id, reference=reference, lease_seconds=60,
                               idempotency_key="round-acquire")
        assert set(handle.input_ids) == set(updates)
        handle = owner.renew(fed.id, handle)
        result = owner.put_record(fed.id, kind="model.global", schema_revision_id=globals_type.id,
            metadata={"base_record_id": initial.id, "inputs": updates}, files={})
        assert_error(lambda: owner.complete(fed.id, replace(handle, fence=handle.fence + 1), result.id),
                     409, "acquisition_not_active")
        complete = owner.complete(fed.id, handle, result.id, idempotency_key="round-complete")
        assert complete.state == "completed" and complete.result_record_id == result.id
        assert owner.resolve(fed.id, "main").record_id == result.id
        assert owner.resolve(fed.id, "main").token != reference.token
        assert_error(lambda: owner.set_ref(fed.id, "main", initial.id, reference=reference), 412,
                     "reference_version_mismatch")
        assert_error(lambda: owner.acquire(fed.id, reference=owner.resolve(fed.id, "main"), input_ids=[]),
                     409, "insufficient_participants")
        checked("fedavg_profile_coordinated_reference_and_fencing",
                participants=2, sample_counts=[16, 24], trained_in_server=False)

        managed = owner.create_space("Managed grant boundary")
        fixture.track_space(managed.id)
        job_id, attempt_id = "sdk-managed-job", "sdk-managed-attempt"
        owner.manage_space(managed.id, job_id=job_id)
        workload_subject = "sdk-worker"
        workload_principal = hashlib.sha256(json.dumps(
            [fixture.workload_issuer, workload_subject], separators=(",", ":")).encode()).hexdigest()
        thumbprint = base64.urlsafe_b64encode(hashlib.sha256(b"independent-workload-certificate").digest()).decode().rstrip("=")
        owner.set_member(managed.id, workload_principal, ["reader"], subject=workload_subject,
                         bindings={"component": "participant"})
        grant = owner.create_workload_grant(managed.id, subject=workload_subject,
            job_id=job_id, attempt_id=attempt_id, component_id="participant", epoch=1,
            expires_at=time.time() + 600, certificate_thumbprint=thumbprint,
            roles=["reader"], bindings={"component": "participant"})
        claims = {"jti": grant.grant_id, "grant_id": grant.grant_id, "space_id": managed.id,
                  "job_id": job_id, "attempt_id": attempt_id, "component_id": "participant",
                  "epoch": 1, "cnf": {"x5t#S256": thumbprint}}
        authorization = "Bearer " + fixture.workload_token(workload_subject, claims)
        target = "/v2/spaces/" + managed.id
        with httpx.Client(verify=ssl.create_default_context(cafile=str(fixture.server_ca)),
                          trust_env=False, timeout=10) as raw:
            no_assertion = raw.get(fixture.managed_endpoint + target,
                                   headers={"Authorization": authorization})
            assert no_assertion.status_code == 401
            headers = assertion(fixture.backend_secret, "GET", target, authorization, thumbprint)
            current = raw.get(fixture.managed_endpoint + target, headers=headers)
            assert current.status_code == 200 and current.json()["id"] == managed.id
            public = raw.get(fixture.endpoint + target, headers=headers)
            assert public.status_code == 401
            owner.revoke_workload_grants(managed.id, attempt_id=attempt_id)
            revoked = raw.get(fixture.managed_endpoint + target,
                headers=assertion(fixture.backend_secret, "GET", target, authorization, thumbprint))
            assert revoked.status_code == 403
        checked("managed_ingress_certificate_bound_grant_revocation")
    except ExchangeError as exc:
        failure = exc
        report["failure"] = {"class": type(exc).__name__, "code": exc.code, "status": exc.status}
    except Exception as exc:
        failure = exc
        report["failure"] = {"class": type(exc).__name__}
        (fixture.root / "failure-traceback.txt").write_text(traceback.format_exc())
    try:
        if failure is None:
            # Restart on retained SQL+S3, without initializing/migrating the database.
            expected = owner.resolve(fed.id, "main")
            fixture.restart_services()
            owner = fixture.client()
            assert owner.resolve(fed.id, "main") == expected
            assert owner.get_record(space.id, bundle.id).state == "published"
            checked("native_restart_retained_reference_and_immutable_record")
            assert not any(name in sys.modules for name in (
                "hf2l_exchange.api", "hf2l_exchange.application", "hf2l_exchange.transfers",
                "hf2l_exchange.worker", "hf2l_exchange.gateway_api"))
            assert sdk_before == {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sdk_paths}
            checked("unchanged_python_sdk_no_python_exchange_server_modules")
    except Exception as exc:
        failure = failure or exc
        report["failure"] = {"class": type(exc).__name__}
        (fixture.root / "failure-traceback.txt").write_text(traceback.format_exc())
    finally:
        try:
            fixture.cleanup()
            report["cleanup_verified"] = True
        except Exception as exc:
            failure = failure or exc
            report["cleanup_verified"] = False
            report["cleanup_failure"] = {"class": type(exc).__name__}
        report["seconds"] = round(time.monotonic() - started, 3)
        report["status"] = "PASS" if failure is None and fixture.cleaned else "FAIL"
        private_json(fixture.root / "result.json", report)
    return report, fixture.root


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--report")
    args = parser.parse_args()
    report, root = run(load_json(args.config))
    if args.report:
        private_json(Path(args.report), report)
    print(json.dumps({"status": report["status"], "passed_checks": len(report["checks"]),
                      "cleanup_verified": report.get("cleanup_verified", False),
                      "result": str(root / "result.json")}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
