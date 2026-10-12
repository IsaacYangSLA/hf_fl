"""Scoped opaque build-product transfer for approved external participant nodes.

The manager verifies file identities against its immutable resource ledger. The
node retains bounded chunks as data; installation occurs only in its sandbox.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import io
import json
import re
from urllib.parse import quote

import httpx

from .collection import CollectionError
from .domain import Error
from .executor import ExecutionIdentity
from .resources import ResourceError
from .workflow import BuiltArtifact

MAX_BUILD_BYTES = 256 * 1024**2
CHUNK_BYTES = 65536
_WHEEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+\-]{0,240}\.whl")


def _manifest(value, *, limit=MAX_BUILD_BYTES):
    if not isinstance(value, dict) or len(value) > 256:
        raise Error(422, "invalid_external_build_manifest")
    validated = {}
    try:
        for name, descriptor in value.items():
            if not isinstance(name, str) or not _WHEEL_NAME.fullmatch(name):
                raise ValueError()
            validated[name] = BuiltArtifact.model_validate(descriptor).model_dump(mode="json")
    except (ValueError, TypeError):
        raise Error(422, "invalid_external_build_manifest") from None
    if sum(item["size_bytes"] for item in validated.values()) > min(MAX_BUILD_BYTES, limit):
        raise Error(413, "external_build_disk_limit")
    return validated


@dataclass
class BuildProduct:
    content: io.BytesIO
    size_bytes: int
    sha256: str
    access_valid: object

    def chunks(self):
        try:
            while chunk := self.content.read(CHUNK_BYTES):
                if not self.access_valid():
                    raise Error(404, "participant_assignment_not_found")
                yield chunk
        finally:
            self.close()

    def close(self):
        self.content.close()


class ExternalBuild:
    """Authorize current external assignment before consulting build files."""

    def __init__(self, service):
        self.service = service

    def _authorized(self, actor):
        if "assignment" not in getattr(actor, "scopes", ()):
            raise Error(403, "node_scope_required")
        expiry = getattr(actor, "expires_at", None)
        if type(expiry) not in (int, float) or expiry <= self.service.manager.now().timestamp():
            raise Error(401, "node_grant_expired")
        with self.service.database.transaction(immediate=False) as session:
            resource, job, attempt, spec, participant, node = self.service._node_record(
                session, actor, active=True)
            session.expunge(job)
        return job, spec, node

    def access_valid(self, actor):
        try:
            self._authorized(actor)
            return True
        except (Error, ValueError):
            return False

    def _manifest(self, job, spec, node):
        try:
            artifacts = self.service.provisioner.build_manifest(job)
        except (ResourceError, CollectionError, OSError):
            raise Error(409, "external_build_not_ready") from None
        validated = _manifest(artifacts, limit=node.resources["disk_bytes"])
        if validated and not any(component.role == "build" for component in spec.components):
            raise Error(409, "external_build_not_approved")
        if not validated and any(component.role == "build" for component in spec.components):
            raise Error(409, "external_build_not_ready")
        return validated

    def manifest(self, actor):
        job, spec, node = self._authorized(actor)
        result = self._manifest(job, spec, node)
        self._authorized(actor)
        return result

    def open_product(self, actor, filename):
        job, spec, node = self._authorized(actor)
        artifacts = self._manifest(job, spec, node)
        if not isinstance(filename, str) or not _WHEEL_NAME.fullmatch(filename) or filename not in artifacts:
            raise Error(404, "participant_build_product_not_found")
        expected = artifacts[filename]
        try:
            content = self.service.provisioner.read_build_product(
                job, filename, max_bytes=expected["size_bytes"])
        except (ResourceError, CollectionError, OSError):
            raise Error(409, "external_build_changed") from None
        if (not isinstance(content, bytes) or len(content) != expected["size_bytes"]
                or hashlib.sha256(content).hexdigest() != expected["sha256"]):
            raise Error(409, "external_build_changed")
        self._authorized(actor)
        return BuildProduct(io.BytesIO(content), expected["size_bytes"], expected["sha256"],
                            lambda: self.access_valid(actor))


def _error_response(response):
    content = bytearray()
    for chunk in response.iter_raw(chunk_size=CHUNK_BYTES):
        if len(content) + len(chunk) > CHUNK_BYTES:
            raise Error(502, "external_build_invalid_reply")
        content.extend(chunk)
    try:
        code = json.loads(content).get("error", {}).get("code")
        if not isinstance(code, str) or not re.fullmatch(r"[a-z0-9_]{1,100}", code):
            raise ValueError()
    except (ValueError, AttributeError, UnicodeError):
        code = "external_build_unavailable"
    raise Error(response.status_code, code)


def stage_products(agent, identity, token, artifacts):
    """Stream approved manager wheels after reserving their full local peak."""
    if not isinstance(identity, ExecutionIdentity):
        raise Error(422, "invalid_external_build_identity")
    assignment = agent.materializer.assignment(identity)
    if assignment.identity != identity or assignment.external_participant_id is None or assignment.pool_id != "external":
        raise Error(403, "external_build_assignment_required")
    validated = _manifest(artifacts, limit=assignment.resources.disk_bytes)
    has_build = any(component.role == "build" for component in assignment.job_spec.components)
    if not validated:
        if has_build:
            raise Error(409, "external_build_not_ready")
        return {}
    if not has_build:
        raise Error(409, "external_build_not_approved")
    if not callable(agent.materializer.auxiliary_reserver):
        raise Error(503, "external_build_accounting_unavailable")
    if not isinstance(token, str) or not 1 <= len(token) <= 16384:
        raise Error(401, "node_grant_required")
    # Reserve both retained source and build inputs before network or file writes.
    total = sum(item["size_bytes"] for item in validated.values())
    agent.materializer._charge_auxiliary(assignment, total)
    receipts = {}
    for filename, expected in sorted(validated.items()):
        endpoint = agent.client.endpoint + agent.client.prefix(identity) + "/build-products/" + quote(filename, safe="")
        offset = 0
        digest = hashlib.sha256()
        try:
            with agent.client.http.stream(
                "GET", endpoint,
                headers={"Authorization": "Bearer " + token, "Accept-Encoding": "identity"},
                follow_redirects=False,
            ) as response:
                if 300 <= response.status_code < 400:
                    raise Error(503, "external_manager_redirect_forbidden")
                if response.status_code >= 400:
                    _error_response(response)
                if response.status_code != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                    raise Error(502, "external_build_invalid_reply")
                length = response.headers.get("Content-Length")
                if length is not None and (not re.fullmatch(r"[0-9]{1,15}", length)
                                           or int(length) != expected["size_bytes"]):
                    raise Error(502, "external_build_size_mismatch")
                for chunk in response.iter_raw(chunk_size=CHUNK_BYTES):
                    if not chunk:
                        continue
                    if offset + len(chunk) > expected["size_bytes"]:
                        raise Error(502, "external_build_size_mismatch")
                    digest.update(chunk)
                    agent.materializer.stage_build_input(identity, validated, filename, offset,
                        base64.b64encode(chunk).decode("ascii"))
                    offset += len(chunk)
        except httpx.HTTPError:
            raise Error(503, "external_build_unavailable") from None
        if offset != expected["size_bytes"]:
            raise Error(502, "external_build_size_mismatch")
        if digest.hexdigest() != expected["sha256"]:
            raise Error(502, "external_build_hash_mismatch")
        receipts[filename] = {"sha256": digest.hexdigest(), "size_bytes": offset}
    return receipts
