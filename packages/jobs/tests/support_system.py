"""Independent HTTP/TLS identity and isolated manager database fixtures.

These are control-plane integration fixtures. They do not simulate sandbox
qualification or claim that a training job has executed.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlencode, urlsplit
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import httpx
import jwt
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url


def free_port():
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]


@contextmanager
def isolated_database(directory):
    """Give each test its own PostgreSQL schema or local SQLite database."""
    base = os.environ.get("JOBS_TEST_DATABASE_URL")
    if not base:
        yield "sqlite:///" + str(Path(directory) / "manager.db")
        return
    schema = "jobs_system_" + uuid.uuid4().hex
    url = make_url(base)
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text('CREATE SCHEMA "' + schema + '"'))
    try:
        yield url.update_query_dict({"options": "-csearch_path=" + schema}).render_as_string(hide_password=False)
    finally:
        try:
            with engine.begin() as connection:
                connection.execute(text('DROP SCHEMA "' + schema + '" CASCADE'))
        finally:
            engine.dispose()


def write_tls_identity(directory):
    directory = Path(directory)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "HF2L synthetic integration issuer")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                        key_encipherment=True, data_encipherment=False, key_agreement=False,
                        key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.DNSName("testserver"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "synthetic-tls.pem", directory / "synthetic-tls-key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    key_path.chmod(0o600)
    return cert_path, key_path


class TLSOIDCProvider:
    """Actual loopback HTTPS OIDC server with one-use S256 authorization codes."""
    def __init__(self, directory):
        self.signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.key_id = "system-fixture-key"
        self.cert_path, self.tls_key_path = write_tls_identity(directory)
        self.subject = "alice"
        self.codes, self.tokens, self.disabled_subjects = {}, {}, set()
        self.requests = []
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, status, body):
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                fixture.requests.append(("GET", urlsplit(self.path).path))
                parts = urlsplit(self.path)
                if parts.path == "/.well-known/openid-configuration":
                    self.reply(200, {"issuer": fixture.issuer, "authorization_endpoint": fixture.issuer + "/authorize",
                                     "token_endpoint": fixture.issuer + "/token", "jwks_uri": fixture.issuer + "/jwks",
                                     "introspection_endpoint": fixture.issuer + "/introspect",
                                     "code_challenge_methods_supported": ["S256"],
                                     "id_token_signing_alg_values_supported": ["RS256"]})
                elif parts.path == "/jwks":
                    key = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(fixture.signing_key.public_key()))
                    key.update(kid=fixture.key_id, use="sig", alg="RS256")
                    self.reply(200, {"keys": [key]})
                elif parts.path == "/authorize":
                    query = {key: value[0] for key, value in parse_qs(parts.query).items()}
                    needed = {"state", "nonce", "code_challenge", "code_challenge_method", "client_id", "redirect_uri"}
                    if not needed.issubset(query) or query["code_challenge_method"] != "S256":
                        self.reply(400, {"error": "PKCE_required"}); return
                    code = secrets.token_urlsafe(24)
                    fixture.codes[code] = {**query, "sub": fixture.subject}
                    target = query["redirect_uri"] + "?" + urlencode({"code": code, "state": query["state"]})
                    self.send_response(302); self.send_header("Location", target)
                    self.send_header("Content-Length", "0"); self.end_headers()
                else:
                    self.reply(404, {"error": "not_found"})

            def do_POST(self):
                fixture.requests.append(("POST", urlsplit(self.path).path))
                size = int(self.headers.get("Content-Length", "0"))
                if size > 65536:
                    self.reply(413, {"error": "request_too_large"}); return
                fields = {key: value[0] for key, value in parse_qs(self.rfile.read(size).decode()).items()}
                if self.path == "/token":
                    code = fixture.codes.pop(fields.get("code"), None)
                    verifier = fields.get("code_verifier", "")
                    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
                    if not code or challenge != code["code_challenge"] or fields.get("client_id") != code["client_id"] or fields.get("redirect_uri") != code["redirect_uri"]:
                        self.reply(400, {"error": "invalid_grant"}); return
                    access = fixture.access_token(code["sub"])
                    now = int(time.time())
                    identity = jwt.encode({"iss": fixture.issuer, "sub": code["sub"], "aud": code["client_id"],
                                           "iat": now, "exp": now + 300, "nonce": code["nonce"],
                                           "sid": "synthetic-session-" + code["sub"]}, fixture.signing_key,
                                          algorithm="RS256", headers={"kid": fixture.key_id})
                    self.reply(200, {"id_token": identity, "access_token": access, "token_type": "Bearer"})
                elif self.path == "/introspect":
                    claims = fixture.tokens.get(fields.get("token"), {})
                    active = bool(claims) and claims["sub"] not in fixture.disabled_subjects
                    self.reply(200, {"active": active, "sub": claims.get("sub"), "iss": fixture.issuer,
                                     "client_id": "integration-client", "aud": "hf2l-jobs",
                                     "exp": claims.get("exp", 0)})
                else:
                    self.reply(404, {"error": "not_found"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.cert_path), str(self.tls_key_path))
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.issuer = "https://127.0.0.1:" + str(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.context = ssl.create_default_context(cafile=str(self.cert_path))
        self.client = httpx.Client(verify=self.context, trust_env=False, follow_redirects=False)

    def close(self):
        self.client.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def access_token(self, subject="alice", **overrides):
        now = int(time.time())
        claims = {"iss": self.issuer, "sub": subject, "aud": "hf2l-jobs", "iat": now,
                  "exp": now + 300, "scope": "jobs"}
        claims.update(overrides)
        token = jwt.encode(claims, self.signing_key, algorithm="RS256",
                           headers={"typ": "at+jwt", "kid": self.key_id})
        self.tokens[token] = claims
        return token

    def authorize(self, authorization_url):
        response = self.client.get(authorization_url)
        if response.status_code != 302:
            raise AssertionError(response.text)
        return response.headers["location"]


@contextmanager
def live_api(app, certificate, private_key):
    """Serve real HTTPS, including unbuffered event streams, in a bounded fixture."""
    import uvicorn
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error",
                            ssl_certfile=str(certificate), ssl_keyfile=str(private_key),
                            access_log=False))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    end = time.monotonic() + 10
    while not server.started:
        if not thread.is_alive() or time.monotonic() > end:
            raise RuntimeError("Synthetic HTTPS manager failed to start")
        time.sleep(.01)
    try:
        yield "https://127.0.0.1:" + str(port)
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        if thread.is_alive():
            server.force_exit = True
