"""Lightweight identity helper shared by Exchange clients and project setup."""
import hashlib
import json


def principal_id(issuer: str, subject: str) -> str:
    """Derive the stable account identifier from its exact issuer and subject."""
    return hashlib.sha256(json.dumps([issuer, subject], separators=(",", ":")).encode()).hexdigest()
