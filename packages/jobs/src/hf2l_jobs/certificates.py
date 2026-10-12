"""Control-plane issuance of fixed-CA, execution-bound client certificates.

Private signing material remains in this issuer. Untrusted requests select only
their public key; requested subjects and extensions never enter issued identity.
Callers durably persist the returned public certificate and CSR digest with the
assignment so retries do not rotate an already active certificate binding.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time
from typing import Callable

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .executor import ExecutionIdentity

MAX_PEM_BYTES = 64 * 1024
MAX_CERTIFICATE_LIFETIME_SECONDS = 30 * 86400
MAX_DEADLINE_GRACE_SECONDS = 300
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class CertificateError(ValueError):
    """An issuance refusal containing no private key, PEM, or file path."""
    code = "certificate_issuance_refused"


def _read_file(path: Path, *, private: bool) -> bytes:
    """Bounded descriptor-relative reads refuse links and mutable key files."""
    parent = descriptor = -1
    try:
        if not path.is_absolute() or ".." in path.parts or path == Path("/"):
            raise CertificateError("Certificate material requires an approved absolute file")
        parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent)
            os.close(parent)
            parent = child
        metadata = os.fstat(parent)
        forbidden = 0o077 if private else 0o022
        if metadata.st_uid not in {0, os.geteuid()} or metadata.st_mode & forbidden:
            raise CertificateError("Certificate material directory permissions are unsafe")
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=parent)
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid not in {0, os.geteuid()} or before.st_mode & forbidden
                or not 0 < before.st_size <= MAX_PEM_BYTES):
            raise CertificateError("Certificate material must be bounded and without unsafe links")
        chunks = bytearray()
        while len(chunks) <= MAX_PEM_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_PEM_BYTES - len(chunks) + 1))
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(descriptor)
        if (len(chunks) > MAX_PEM_BYTES or len(chunks) != after.st_size
                or (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise CertificateError("Certificate material changed while being read")
        return bytes(chunks)
    except (OSError, ValueError):
        raise CertificateError("Approved certificate material is unavailable") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent >= 0:
            os.close(parent)


def _pem(value, *, labels, private=False):
    if isinstance(value, Path):
        value = _read_file(value, private=private)
    elif isinstance(value, str):
        if not 0 < len(value) <= MAX_PEM_BYTES:
            raise CertificateError("Certificate material exceeds permitted bounds")
        if value.lstrip().startswith("-----BEGIN "):
            try:
                value = value.encode("ascii")
            except UnicodeError:
                raise CertificateError("Invalid certificate material") from None
        else:
            value = _read_file(Path(value), private=private)
    if not isinstance(value, bytes) or not 0 < len(value) <= MAX_PEM_BYTES:
        raise CertificateError("Certificate material exceeds permitted bounds")
    value = value.strip()
    for label in labels:
        begin, end = ("-----BEGIN " + label + "-----").encode(), ("-----END " + label + "-----").encode()
        if value.startswith(begin) and value.endswith(end):
            middle = value[len(begin):-len(end)]
            if b"-----BEGIN " not in middle and b"-----END " not in middle:
                return value
    raise CertificateError("Expected one approved PEM block")


def _approved_public_key(key):
    return ((isinstance(key, rsa.RSAPublicKey) and 2048 <= key.key_size <= 8192
             and key.public_numbers().e == 65537)
            or (isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)))


def validate_csr(csr_pem) -> x509.CertificateSigningRequest:
    """Validate an untrusted CSR before starting any durable provisioning work.

    This pure preflight reads no files, accesses no CA, and signs no certificate.
    The returned object contains only the request's public key and signed data.
    """
    if (not isinstance(csr_pem, (bytes, str))
            or not 0 < len(csr_pem) <= MAX_PEM_BYTES
            or (isinstance(csr_pem, str) and not csr_pem.lstrip().startswith("-----BEGIN "))):
        raise CertificateError("Certificate request must contain bounded PEM bytes or text")
    try:
        csr = x509.load_pem_x509_csr(
            _pem(csr_pem, labels=("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST")))
        public = csr.public_key()
        if (not csr.is_signature_valid or not isinstance(public, rsa.RSAPublicKey)
                or not _approved_public_key(public)):
            raise CertificateError("CSR requires a valid RSA key and signature")
        # Caller-selected CA, SAN, key usage, or any other authority is forbidden.
        if len(csr.extensions):
            raise CertificateError("CSR extensions are not permitted")
        return csr
    except (ValueError, TypeError, x509.DuplicateExtension, x509.UnsupportedGeneralNameType,
            OverflowError, OSError, UnsupportedAlgorithm):
        raise CertificateError("Certificate signing request was refused") from None


def _binding(identity, space_id):
    if not isinstance(identity, ExecutionIdentity):
        raise CertificateError("Certificate requires a validated execution identity")
    if (not isinstance(space_id, str) or not _IDENTIFIER.fullmatch(space_id)
            or type(identity.epoch) is not int or not 1 <= identity.epoch < 1 << 63):
        raise CertificateError("Invalid certificate execution binding")
    # Revalidate even identities reconstructed by trusted serialization helpers.
    for value in (identity.job_id, identity.attempt_id, identity.component_id):
        if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
            raise CertificateError("Invalid certificate execution binding")
    return json.dumps([identity.job_id, identity.attempt_id, identity.component_id,
                       identity.epoch, space_id], separators=(",", ":")).encode("utf-8")


class CertificateIssuer:
    """Fixed trusted CA; issue client-only certificates for one execution."""

    def __init__(self, ca_certificate, ca_private_key, *,
                 clock: Callable[[], float] = time.time,
                 grace_seconds: int = MAX_DEADLINE_GRACE_SECONDS,
                 max_lifetime_seconds: int = MAX_CERTIFICATE_LIFETIME_SECONDS):
        if (type(grace_seconds) is not int or not 0 <= grace_seconds <= MAX_DEADLINE_GRACE_SECONDS
                or type(max_lifetime_seconds) is not int
                or not 1 <= max_lifetime_seconds <= MAX_CERTIFICATE_LIFETIME_SECONDS):
            raise CertificateError("Certificate lifetime policy exceeds permitted bounds")
        try:
            certificate = (ca_certificate if isinstance(ca_certificate, x509.Certificate)
                           else x509.load_pem_x509_certificate(
                               _pem(ca_certificate, labels=("CERTIFICATE",))))
            key = ca_private_key
            if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
                key = serialization.load_pem_private_key(
                    _pem(key, labels=("PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"), private=True),
                    password=None)
            public = certificate.public_key()
            if (not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey))
                    or not _approved_public_key(public) or not _approved_public_key(key.public_key())
                    or public.public_bytes(serialization.Encoding.DER,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)
                    != key.public_key().public_bytes(serialization.Encoding.DER,
                                                     serialization.PublicFormat.SubjectPublicKeyInfo)):
                raise CertificateError("CA certificate and signing key must match an approved key")
            constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
            if not constraints.ca:
                raise CertificateError("Signing certificate must be a trusted CA")
            try:
                usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
                if not usage.key_cert_sign:
                    raise CertificateError("CA key cannot sign certificates")
            except x509.ExtensionNotFound:
                pass
        except (ValueError, TypeError, x509.ExtensionNotFound, x509.DuplicateExtension, UnsupportedAlgorithm):
            raise CertificateError("Invalid trusted CA certificate or signing key") from None
        self.clock = clock
        self.grace_seconds = grace_seconds
        self.max_lifetime_seconds = max_lifetime_seconds
        self._certificate = certificate
        self._private_key = key
        self._ca_validity(self._now())

    def __repr__(self):
        return "<CertificateIssuer fixed trusted CA>"

    def _now(self):
        try:
            value = self.clock()
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise ValueError()
            return datetime.fromtimestamp(value, timezone.utc)
        except (ValueError, TypeError, OverflowError, OSError):
            raise CertificateError("Trusted certificate clock is unavailable") from None

    def _ca_validity(self, now):
        if not self._certificate.not_valid_before_utc <= now < self._certificate.not_valid_after_utc:
            raise CertificateError("Trusted CA is outside its validity interval")

    validate_csr = staticmethod(validate_csr)

    def issue(self, csr_pem, identity: ExecutionIdentity, space_id: str, deadline: float) -> dict:
        binding = _binding(identity, space_id)
        now = self._now()
        self._ca_validity(now)
        try:
            if type(deadline) not in (int, float):
                raise ValueError()
            deadline = float(deadline)
            if not math.isfinite(deadline) or deadline <= now.timestamp():
                raise ValueError()
        except (ValueError, TypeError, OverflowError):
            raise CertificateError("Certificate requires an unexpired immutable job deadline") from None
        csr = validate_csr(csr_pem)
        public = csr.public_key()
        try:
            expires = min(deadline + self.grace_seconds,
                          now.timestamp() + self.max_lifetime_seconds,
                          self._certificate.not_valid_after_utc.timestamp())
            until = datetime.fromtimestamp(expires, timezone.utc).replace(microsecond=0)
            start = max(now - timedelta(seconds=30), self._certificate.not_valid_before_utc)
            start = start.replace(microsecond=0)
            if until <= now:
                raise CertificateError("Certificate validity cannot extend beyond trusted bounds")
            subject = x509.Name([x509.NameAttribute(
                NameOID.COMMON_NAME, hashlib.sha256(binding).hexdigest())])
            try:
                issuer_identifier = self._certificate.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier).value
            except x509.ExtensionNotFound:
                issuer_identifier = x509.SubjectKeyIdentifier.from_public_key(
                    self._certificate.public_key())
            certificate = (x509.CertificateBuilder()
                .subject_name(subject).issuer_name(self._certificate.subject)
                .public_key(public).serial_number(x509.random_serial_number())
                .not_valid_before(start).not_valid_after(until)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    issuer_identifier), critical=False)
                .add_extension(x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .sign(self._private_key, hashes.SHA256()))
        except (ValueError, TypeError, x509.DuplicateExtension, x509.UnsupportedGeneralNameType,
                OverflowError, OSError, UnsupportedAlgorithm):
            raise CertificateError("Certificate signing request was refused") from None
        encoded = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
        thumbprint = base64.urlsafe_b64encode(
            certificate.fingerprint(hashes.SHA256())).decode("ascii").rstrip("=")
        return {"certificate_pem": encoded, "certificate_thumbprint": thumbprint,
                "expires_at": certificate.not_valid_after_utc.timestamp()}
