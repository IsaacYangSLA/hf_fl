"""Real certificate/CSR security contracts; synthetic private keys only."""
from __future__ import annotations
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import shutil
import ssl
import subprocess
import time
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from fastapi import FastAPI, Request
import httpx

from hf2l_jobs.certificates import CertificateError, CertificateIssuer, validate_csr
from hf2l_jobs.executor import ExecutionIdentity


class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.now = datetime(2026, 10, 9, 12, 0, 0, tzinfo=timezone.utc)
        self.identity = ExecutionIdentity("job-a", "attempt-a", "owner", 1)
        self.ca = self.make_ca()
        self.issuer = CertificateIssuer(self.ca.public_bytes(serialization.Encoding.PEM),
                                       self.key_bytes(), clock=lambda: self.now.timestamp())

    def key_bytes(self, key=None):
        return (key or self.key).private_bytes(serialization.Encoding.PEM,
                                              serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption())

    def make_ca(self, *, key=None, ca=True, before=None, after=None, can_sign=True, identifier=None):
        key = key or self.key
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic test CA")])
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(before or self.now - timedelta(days=1))
                .not_valid_after(after or self.now + timedelta(days=90))
                .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
                .add_extension(identifier or x509.SubjectKeyIdentifier.from_public_key(
                    key.public_key()), critical=False)
                .add_extension(x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=can_sign,
                    crl_sign=can_sign, encipher_only=False, decipher_only=False), critical=True)
                .sign(key, hashes.SHA256()))

    def csr(self, *, key=None, extensions=()):
        builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "attacker-selected-identity")]))
        for extension, critical in extensions:
            builder = builder.add_extension(extension, critical)
        return builder.sign(key or self.client_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)

    def issue(self, **changes):
        values = dict(csr_pem=self.csr(), identity=self.identity,
                      space_id="space-a", deadline=self.now.timestamp() + 3600)
        values.update(changes)
        return self.issuer.issue(**values)

    def certificate(self, result):
        return x509.load_pem_x509_certificate(result["certificate_pem"].encode("ascii"))

    def test_csr_preflight_accepts_bytes_text_and_static_contract(self):
        pem = self.csr()
        for csr in (validate_csr(pem), validate_csr(pem.decode("ascii")),
                    CertificateIssuer.validate_csr(pem), self.issuer.validate_csr(pem)):
            self.assertIsInstance(csr, x509.CertificateSigningRequest)
            self.assertTrue(csr.is_signature_valid)
            self.assertEqual(csr.public_key().public_numbers(),
                             self.client_key.public_key().public_numbers())

    def test_invalid_csr_preflight_performs_no_issuance_or_file_read(self):
        # Integration callers invoke this pure function before opening their
        # resource-ledger operation; refusal cannot create an issuance effect.
        with mock.patch("hf2l_jobs.certificates._read_file") as read_file, \
                mock.patch("hf2l_jobs.certificates.x509.CertificateBuilder") as builder, \
                mock.patch("hf2l_jobs.certificates.x509.random_serial_number") as serial:
            invalid = [b"malformed-csr", b"x" * (65536 + 1), "/tmp/request.csr",
                       Path("/tmp/request.csr"),
                       self.csr(extensions=[(x509.BasicConstraints(ca=True, path_length=None), True)])]
            for value in invalid:
                with self.subTest(type=type(value)), self.assertRaises(CertificateError):
                    validate_csr(value)
            read_file.assert_not_called()
            builder.assert_not_called()
            serial.assert_not_called()

    def test_issue_uses_the_shared_csr_preflight(self):
        with mock.patch("hf2l_jobs.certificates.validate_csr", wraps=validate_csr) as preflight:
            result = self.issue()
            preflight.assert_called_once()
        self.assertIsInstance(self.certificate(result), x509.Certificate)

    def test_client_only_extensions_and_real_ca_signature(self):
        result = self.issue()
        cert = self.certificate(result)
        self.key.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                                     padding.PKCS1v15(), cert.signature_hash_algorithm)
        self.assertEqual(cert.issuer, self.ca.subject)
        self.assertEqual(cert.public_key().public_numbers(), self.client_key.public_key().public_numbers())
        self.assertEqual(set(result), {"certificate_pem", "certificate_thumbprint", "expires_at"})
        self.assertEqual(len(cert.extensions), 5)
        subject_identifier = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        authority_identifier = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        self.assertFalse(subject_identifier.critical)
        self.assertFalse(authority_identifier.critical)
        self.assertEqual(subject_identifier.value,
                         x509.SubjectKeyIdentifier.from_public_key(self.client_key.public_key()))
        self.assertEqual(authority_identifier.value.key_identifier,
                         self.ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest)
        self.assertTrue(cert.extensions.get_extension_for_class(x509.KeyUsage).critical)
        self.assertFalse(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(usage.digital_signature)
        for name in ("content_commitment", "key_encipherment", "data_encipherment",
                     "key_agreement", "key_cert_sign", "crl_sign"):
            self.assertFalse(getattr(usage, name))
        self.assertEqual(list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value),
                         [ExtendedKeyUsageOID.CLIENT_AUTH])

    def test_authority_identifier_matches_custom_trusted_ca_identifier(self):
        identifier = x509.SubjectKeyIdentifier(b"trusted-custom-key-identifier")
        ca = self.make_ca(identifier=identifier)
        issuer = CertificateIssuer(ca, self.key, clock=lambda: self.now.timestamp())
        cert = self.certificate(issuer.issue(
            self.csr(), self.identity, "space-a", self.now.timestamp() + 3600))
        self.assertEqual(cert.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier).value.key_identifier, identifier.digest)

    def test_legacy_ca_without_identifier_uses_public_key_identifier(self):
        builder = (x509.CertificateBuilder().subject_name(self.ca.subject)
                   .issuer_name(self.ca.issuer).public_key(self.ca.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(self.ca.not_valid_before_utc)
                   .not_valid_after(self.ca.not_valid_after_utc))
        for extension in self.ca.extensions:
            if not isinstance(extension.value, x509.SubjectKeyIdentifier):
                builder = builder.add_extension(extension.value, critical=extension.critical)
        ca = builder.sign(self.key, hashes.SHA256())
        issuer = CertificateIssuer(ca, self.key, clock=lambda: self.now.timestamp())
        cert = self.certificate(issuer.issue(
            self.csr(), self.identity, "space-a", self.now.timestamp() + 3600))
        self.assertEqual(cert.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier).value,
            x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()))
        from hf2l_jobs.execution_proxy import ProxySupervisor
        from hf2l_jobs.managed_client import ManagedArtifactBroker
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            ca_path, key_path = root / "ca.pem", root / "ca.key"
            ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(self.key_bytes())
            key_path.chmod(0o600)
            supervisor = ProxySupervisor(root / "proxy", client_ca_certificate=str(ca_path),
                client_ca_key=str(key_path), broker=None, exchange_endpoint="https://localhost",
                gateway_endpoint="https://localhost", service_ca_file=str(ca_path),
                grant_lookup=lambda *args: None)
            self.addCleanup(supervisor.close)
            _, _, proxy_path, _ = supervisor._materialize(
                "job-a", "attempt-a", "owner", "space-a", 1, time.time() + 600)
            broker = ManagedArtifactBroker(None, None, None, None, root / "artifacts",
                client_ca_certificate=str(ca_path), client_ca_key=str(key_path),
                gateway_endpoint="https://localhost", service_ca_file=str(ca_path))
            _, artifact_path, _, _, _ = broker._certificate("job-a", "request-a")
            for path in (proxy_path, artifact_path):
                cert = x509.load_pem_x509_certificate(Path(path).read_bytes())
                self.assertEqual(cert.extensions.get_extension_for_class(
                    x509.AuthorityKeyIdentifier).value,
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()))

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL executable required for strict-chain proof")
    def test_openssl_strict_client_chain_preserves_client_only_purpose(self):
        cases = [(self.key, None), (ec.generate_private_key(ec.SECP256R1()), None),
                 (self.key, x509.SubjectKeyIdentifier(b"trusted-custom-key-identifier"))]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for key, identifier in cases:
                with self.subTest(ca_type=type(key).__name__, custom_identifier=identifier is not None):
                    ca = self.make_ca(key=key, identifier=identifier)
                    issuer = CertificateIssuer(ca, key, clock=lambda: self.now.timestamp())
                    cert = self.certificate(issuer.issue(
                        self.csr(), self.identity, "space-a", self.now.timestamp() + 3600))
                    ca_path, cert_path = root / "ca.pem", root / "client.pem"
                    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
                    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
                    command = [shutil.which("openssl"), "verify", "-x509_strict", "-attime",
                               str(int(self.now.timestamp())), "-CAfile", str(ca_path)]
                    accepted = subprocess.run(command + ["-purpose", "sslclient", str(cert_path)],
                                              capture_output=True, text=True, timeout=10)
                    self.assertEqual(accepted.returncode, 0, accepted.stderr)
                    rejected = subprocess.run(command + ["-purpose", "sslserver", str(cert_path)],
                                              capture_output=True, text=True, timeout=10)
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertIn("unsuitable certificate purpose", rejected.stderr)

    def test_strict_mtls_accepts_all_production_issuance_paths(self):
        from hf2l_jobs.execution_proxy import ProxySupervisor, start_mtls_server
        from hf2l_jobs.gateway import certificate_thumbprint, tls_context
        from hf2l_jobs.managed_client import ManagedArtifactBroker

        self.now = datetime.now(timezone.utc)
        ca = self.make_ca(identifier=x509.SubjectKeyIdentifier(b"strict-custom-ca-identifier"))
        issuer = CertificateIssuer(ca, self.key)
        server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        server_cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(ca.subject).public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(self.now - timedelta(minutes=1))
            .not_valid_after(self.now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value), critical=False)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(self.key, hashes.SHA256()))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            def write(name, data):
                path = root / name
                path.write_bytes(data)
                path.chmod(0o600)
                return str(path)
            ca_file = write("ca.pem", ca.public_bytes(serialization.Encoding.PEM))
            ca_key = write("ca.key", self.key_bytes())
            server_file = write("server.pem", server_cert.public_bytes(serialization.Encoding.PEM))
            server_key_file = write("server.key", self.key_bytes(server_key))
            central = issuer.issue(self.csr(), self.identity, "space-a", time.time() + 600)
            central_file = write("central.pem", central["certificate_pem"].encode("ascii"))
            central_key_file = write("central.key", self.key_bytes(self.client_key))
            supervisor = ProxySupervisor(root / "proxy", client_ca_certificate=ca_file,
                client_ca_key=ca_key, broker=None, exchange_endpoint="https://localhost",
                gateway_endpoint="https://localhost", service_ca_file=ca_file,
                grant_lookup=lambda *args: None)
            self.addCleanup(supervisor.close)
            binding, _, proxy_file, proxy_key_file = supervisor._materialize(
                "job-a", "attempt-a", "owner", "space-a", 1, time.time() + 600)
            broker = ManagedArtifactBroker(None, None, None, None, root / "artifacts",
                client_ca_certificate=ca_file, client_ca_key=ca_key,
                gateway_endpoint="https://localhost", service_ca_file=ca_file)
            _, artifact_file, artifact_key_file, artifact_thumbprint, _ = broker._certificate(
                "job-a", "request-a")
            app = FastAPI()
            @app.get("/health")
            def health(request: Request):
                return {"thumbprint": request.scope["state"]["verified_certificate_thumbprint"]}
            server = start_mtls_server(app, certificate=server_file, key=server_key_file, client_ca=ca_file)
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            original_server_flags = server.socket.context.verify_flags
            server.socket.context.verify_flags |= ssl.VERIFY_X509_STRICT
            self.assertEqual(server.socket.context.verify_flags & original_server_flags,
                             original_server_flags)
            cases = [("central", central_file, central_key_file, central["certificate_thumbprint"]),
                     ("proxy", str(proxy_file), str(proxy_key_file), binding.certificate_thumbprint),
                     ("artifact", artifact_file, artifact_key_file, artifact_thumbprint)]
            for label, cert_file, key_file, expected_thumbprint in cases:
                with self.subTest(path=label):
                    cert = x509.load_pem_x509_certificate(Path(cert_file).read_bytes())
                    self.assertEqual(len(cert.extensions), 5)
                    self.assertEqual(cert.extensions.get_extension_for_class(
                        x509.SubjectKeyIdentifier).value,
                        x509.SubjectKeyIdentifier.from_public_key(cert.public_key()))
                    self.assertEqual(cert.extensions.get_extension_for_class(
                        x509.AuthorityKeyIdentifier).value.key_identifier,
                        ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest)
                    usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
                    self.assertTrue(usage.critical)
                    self.assertTrue(usage.value.digital_signature)
                    self.assertFalse(usage.value.key_cert_sign)
                    self.assertFalse(usage.value.crl_sign)
                    if shutil.which("openssl"):
                        verified = subprocess.run([shutil.which("openssl"), "verify", "-x509_strict",
                            "-purpose", "sslclient", "-CAfile", ca_file, cert_file],
                            capture_output=True, text=True, timeout=10)
                        self.assertEqual(verified.returncode, 0, verified.stderr)
                    context = tls_context(ca_file, cert_file, key_file)
                    original_client_flags = context.verify_flags
                    context.verify_flags |= ssl.VERIFY_X509_STRICT
                    self.assertEqual(context.verify_flags & original_client_flags, original_client_flags)
                    self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
                    self.assertTrue(context.check_hostname)
                    with httpx.Client(verify=context, trust_env=False, timeout=5) as client:
                        response = client.get("https://localhost:" + str(server.server_address[1]) + "/health")
                    self.assertEqual(response.status_code, 200, response.text)
                    self.assertEqual(response.json()["thumbprint"], expected_thumbprint)
                    self.assertEqual(expected_thumbprint,
                                     certificate_thumbprint(cert.public_bytes(serialization.Encoding.DER)))
            context = tls_context(ca_file)
            context.verify_flags |= ssl.VERIFY_X509_STRICT
            with httpx.Client(verify=context, trust_env=False, timeout=5) as client:
                with self.assertRaises(httpx.HTTPError):
                    client.get("https://localhost:" + str(server.server_address[1]) + "/health")

    def test_thumbprint_matches_der_sha256_and_not_private_key(self):
        result = self.issue()
        cert = self.certificate(result)
        expected = base64.urlsafe_b64encode(hashlib.sha256(
            cert.public_bytes(serialization.Encoding.DER)).digest()).decode().rstrip("=")
        self.assertEqual(result["certificate_thumbprint"], expected)
        self.assertEqual(len(expected), 43)
        self.assertEqual(result["expires_at"], cert.not_valid_after_utc.timestamp())
        for text in (repr(self.issuer), repr(result), str(self.issuer)):
            self.assertNotIn("PRIVATE KEY", text)
            self.assertNotIn(self.key_bytes().decode().splitlines()[2], text)

    def test_subject_is_server_opaque_full_execution_and_space_binding(self):
        result = self.issue()
        cert = self.certificate(result)
        expected = hashlib.sha256(json.dumps(
            ["job-a", "attempt-a", "owner", 1, "space-a"], separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(cert.subject, x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, expected)]))
        subjects = {cert.subject.rfc4514_string()}
        for identity, space in [
            (ExecutionIdentity("job-b", "attempt-a", "owner", 1), "space-a"),
            (ExecutionIdentity("job-a", "attempt-b", "owner", 1), "space-a"),
            (ExecutionIdentity("job-a", "attempt-a", "client", 1), "space-a"),
            (ExecutionIdentity("job-a", "attempt-a", "owner", 2), "space-a"),
            (self.identity, "space-b")]:
            subjects.add(self.certificate(self.issue(identity=identity, space_id=space)).subject.rfc4514_string())
        self.assertEqual(len(subjects), 6)
        self.assertNotIn("attacker-selected", cert.subject.rfc4514_string())

    def test_every_requested_extension_is_rejected(self):
        extensions = [
            x509.BasicConstraints(ca=True, path_length=None),
            x509.SubjectAlternativeName([x509.DNSName("manager.example.test")]),
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4"), b"untrusted"),
        ]
        for extension in extensions:
            with self.subTest(extension=extension), self.assertRaises(CertificateError):
                self.issue(csr_pem=self.csr(extensions=[(extension, False)]))

    def test_signature_tampering_is_rejected(self):
        csr = x509.load_pem_x509_csr(self.csr())
        der = bytearray(csr.public_bytes(serialization.Encoding.DER))
        der[-1] ^= 1
        pem = b"-----BEGIN CERTIFICATE REQUEST-----\n" + base64.encodebytes(bytes(der)) + b"-----END CERTIFICATE REQUEST-----\n"
        with self.assertRaises(CertificateError):
            self.issue(csr_pem=pem)

    def test_weak_unsupported_and_nonstandard_exponent_csr_keys_rejected(self):
        keys = [rsa.generate_private_key(public_exponent=65537, key_size=1024),
                rsa.generate_private_key(public_exponent=3, key_size=2048),
                ec.generate_private_key(ec.SECP256R1())]
        for key in keys:
            with self.subTest(key=key), self.assertRaises(CertificateError):
                self.issue(csr_pem=self.csr(key=key))

    def test_csr_bound_and_only_one_pem_block(self):
        for value in (b"", None, self.csr() * 2, b"a" * (65536 + 1),
                      "not a certificate", Path("/tmp/csr"), "/tmp/csr", True, self.ca.public_bytes(serialization.Encoding.PEM)):
            with self.subTest(value_type=type(value)), self.assertRaises(CertificateError):
                self.issue(csr_pem=value)

    def test_deadline_plus_grace_cap(self):
        result = self.issue(deadline=self.now.timestamp() + 600)
        self.assertEqual(result["expires_at"], self.now.timestamp() + 900)
        issuer = CertificateIssuer(self.ca, self.key, clock=lambda: self.now.timestamp(), grace_seconds=0)
        result = issuer.issue(self.csr(), self.identity, "space-a", self.now.timestamp() + 600)
        self.assertEqual(result["expires_at"], self.now.timestamp() + 600)

    def test_maximum_thirty_day_lifetime_cap(self):
        result = self.issue(deadline=self.now.timestamp() + 90 * 86400)
        self.assertEqual(result["expires_at"], self.now.timestamp() + 30 * 86400)
        issuer = CertificateIssuer(self.ca, self.key, clock=lambda: self.now.timestamp(),
                                   max_lifetime_seconds=600)
        result = issuer.issue(self.csr(), self.identity, "space-a", self.now.timestamp() + 3600)
        self.assertEqual(result["expires_at"], self.now.timestamp() + 600)

    def test_ca_expiry_cap_and_validity_checked_again_per_issue(self):
        ca = self.make_ca(after=self.now + timedelta(seconds=120))
        issuer = CertificateIssuer(ca, self.key, clock=lambda: self.now.timestamp())
        result = issuer.issue(self.csr(), self.identity, "space-a", self.now.timestamp() + 3600)
        self.assertEqual(result["expires_at"], self.now.timestamp() + 120)
        self.now += timedelta(seconds=120)
        with self.assertRaises(CertificateError):
            issuer.issue(self.csr(), self.identity, "space-a", self.now.timestamp() + 3600)

    def test_expired_future_non_ca_or_disallowed_ca_rejected(self):
        candidates = [
            self.make_ca(after=self.now - timedelta(seconds=1)),
            self.make_ca(before=self.now + timedelta(seconds=1)),
            self.make_ca(ca=False), self.make_ca(can_sign=False),
            self.make_ca(key=ec.generate_private_key(ec.SECP384R1()))]
        for ca in candidates:
            with self.subTest(ca=ca), self.assertRaises(CertificateError):
                CertificateIssuer(ca, self.key, clock=lambda: self.now.timestamp())

    def test_ca_certificate_private_key_mismatch_rejected(self):
        with self.assertRaises(CertificateError) as refusal:
            CertificateIssuer(self.ca, self.other_key, clock=lambda: self.now.timestamp())
        self.assertNotIn("PRIVATE KEY", str(refusal.exception))
        self.assertIsNone(refusal.exception.__cause__)

    def test_p256_fixed_ca_can_issue_rsa_clients(self):
        key = ec.generate_private_key(ec.SECP256R1())
        ca = self.make_ca(key=key)
        issuer = CertificateIssuer(ca, key, clock=lambda: self.now.timestamp())
        cert = self.certificate(issuer.issue(
            self.csr(), self.identity, "space-a", self.now.timestamp() + 3600))
        key.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                                ec.ECDSA(cert.signature_hash_algorithm))
        self.assertIsInstance(cert.public_key(), rsa.RSAPublicKey)

    def test_invalid_deadlines_and_binding_rejected(self):
        for deadline in (True, None, float("inf"), float("nan"), self.now.timestamp(), -1, 1 << 1024):
            with self.subTest(deadline=deadline), self.assertRaises(CertificateError):
                self.issue(deadline=deadline)
        for space in ("../other", "", None, "a" * 129):
            with self.subTest(space=space), self.assertRaises(CertificateError):
                self.issue(space_id=space)
        with self.assertRaises(CertificateError):
            self.issue(identity={"job_id": "job-a"})
        with self.assertRaises(CertificateError):
            self.issue(identity=ExecutionIdentity("job-a", "attempt-a", "owner", 1 << 63))

    def test_untrusted_lifetime_settings_rejected(self):
        for settings in ({"grace_seconds": 301}, {"grace_seconds": -1}, {"grace_seconds": True},
                         {"max_lifetime_seconds": 30 * 86400 + 1},
                         {"max_lifetime_seconds": 0}, {"max_lifetime_seconds": True}):
            with self.subTest(settings=settings), self.assertRaises(CertificateError):
                CertificateIssuer(self.ca, self.key, **settings, clock=lambda: self.now.timestamp())

    def test_file_loading_private_permissions_links_and_directory_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            cert = root / "ca.pem"
            key = root / "key.pem"
            cert.write_bytes(self.ca.public_bytes(serialization.Encoding.PEM))
            key.write_bytes(self.key_bytes())
            cert.chmod(0o644); key.chmod(0o600)
            issuer = CertificateIssuer(cert, str(key), clock=lambda: self.now.timestamp())
            self.assertIn("certificate_pem", issuer.issue(
                self.csr(), self.identity, "space-a", self.now.timestamp() + 3600))
            key.chmod(0o644)
            with self.assertRaises(CertificateError):
                CertificateIssuer(cert, key, clock=lambda: self.now.timestamp())
            key.chmod(0o600)
            symlink = root / "link"
            symlink.symlink_to(key)
            with self.assertRaises(CertificateError):
                CertificateIssuer(cert, symlink, clock=lambda: self.now.timestamp())
            hardlink = root / "hardlink"
            os.link(key, hardlink)
            with self.assertRaises(CertificateError):
                CertificateIssuer(cert, key, clock=lambda: self.now.timestamp())
            hardlink.unlink()
            root.chmod(0o755)
            with self.assertRaises(CertificateError):
                CertificateIssuer(cert, key, clock=lambda: self.now.timestamp())

    def test_malformed_material_does_not_leak_private_bytes_or_path(self):
        sentinel = b"-----BEGIN PRIVATE KEY-----\nsecret-material\n-----END PRIVATE KEY-----"
        for value in (sentinel, b"other-secret", self.key_bytes() * 2):
            with self.subTest(value_size=len(value)), self.assertRaises(CertificateError) as error:
                CertificateIssuer(self.ca, value, clock=lambda: self.now.timestamp())
            self.assertNotIn("secret-material", str(error.exception))
            self.assertNotIn("PRIVATE KEY", str(error.exception))
        with self.assertRaises(CertificateError) as error:
            CertificateIssuer(self.ca, "/does/not/exist/private.pem", clock=lambda: self.now.timestamp())
        self.assertNotIn("/does/not/exist", str(error.exception))

    def test_invalid_trusted_clock_refuses_issuance(self):
        for value in (True, float("nan"), float("inf"), None):
            with self.subTest(value=value), self.assertRaises(CertificateError):
                CertificateIssuer(self.ca, self.key, clock=lambda: value)

    def test_reissuing_returns_only_public_material_with_fresh_serial(self):
        first, second = self.issue(), self.issue()
        self.assertNotEqual(first["certificate_thumbprint"], second["certificate_thumbprint"])
        self.assertEqual(self.certificate(first).subject, self.certificate(second).subject)
        self.assertEqual(self.certificate(first).public_key().public_numbers(),
                         self.certificate(second).public_key().public_numbers())


if __name__ == "__main__":
    unittest.main()
