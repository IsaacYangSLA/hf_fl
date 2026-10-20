"""Focused bootstrap security/configuration checks; live workflow is verify.py."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("first_federation_stack", SOURCE / "stack.py")
stack = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stack)


class StackConfigurationTests(unittest.TestCase):
    def initialize(self, directory, *extra):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = stack.main([
                "--runtime-dir", str(directory), "init",
                "--exchange-host", "exchange.example.org",
                "--auth-host", "auth.example.org",
                "--objects-host", "objects.example.org",
                *extra,
            ])
        self.assertEqual(code, 0, output.getvalue())
        return output.getvalue()

    def test_private_config_separate_subject_receipt_and_tls(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "operator"
            output = self.initialize(runtime)
            config = stack.load_json(runtime / "config.json")
            accounts = stack.load_json(runtime / "accounts.json")
            self.assertEqual(stat.S_IMODE(runtime.stat().st_mode), 0o700)
            for name in ("config.json", "accounts.json", "compose.env", "exchange.env", "db-init.sql"):
                self.assertEqual(stat.S_IMODE((runtime / name).stat().st_mode), 0o600)
            self.assertEqual(config["issuer"], "https://auth.example.org/realms/hf2l")
            self.assertEqual(config["client_id"], "hf2l-cli")
            self.assertFalse((runtime / "identities.json").exists())
            passwords = [row["password"] for row in accounts["accounts"].values()]
            passwords.append(accounts["keycloak_admin"]["password"])
            self.assertEqual(len(set(passwords)), 5)
            for password in passwords:
                self.assertNotIn(password, output)
            self.assertIn("EXCHANGE_S3_ENDPOINT=https://objects.example.org\n",
                          (runtime / "exchange.env").read_text())
            self.assertNotIn("ALLOW_LOCAL_HTTP", (runtime / "exchange.env").read_text())

    def test_internal_ca_mode_and_nonstandard_https_port(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "operator"
            self.initialize(runtime, "--tls", "internal", "--https-port", "9443",
                            "--http-port", "9080", "--access-token-seconds", "30")
            self.assertEqual((runtime / "tls.conf").read_text(), "tls internal\n")
            config = stack.load_json(runtime / "config.json")
            self.assertEqual(config["issuer"], "https://auth.example.org:9443/realms/hf2l")
            self.assertEqual(config["access_token_seconds"], 30)

    def test_device_client_cannot_use_password_or_implicit_grants(self):
        accounts = {"accounts": {name: {"password": "not-a-real-password"} for name in stack.ACCOUNTS}}
        realm = stack.realm_document(accounts, 300)
        client = realm["clients"][0]
        self.assertTrue(client["publicClient"])
        self.assertFalse(client["directAccessGrantsEnabled"])
        self.assertFalse(client["implicitFlowEnabled"])
        self.assertFalse(client["serviceAccountsEnabled"])
        self.assertEqual(client["attributes"]["access.token.header.type.rfc9068"], "true")
        self.assertEqual(client["attributes"]["oauth2.device.authorization.grant.enabled"], "true")
        self.assertEqual(client["attributes"]["access.token.signed.response.alg"], "RS256")
        self.assertIn("exchange", client["defaultClientScopes"])
        self.assertEqual(next(scope for scope in realm["clientScopes"] if scope["name"] == "exchange")["protocolMappers"][0]["config"]["included.custom.audience"], "exchange")

    def test_reinitialization_preserves_existing_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "operator"
            self.initialize(runtime)
            original = (runtime / "accounts.json").read_bytes()
            with contextlib.redirect_stderr(io.StringIO()):
                code = stack.main(["--runtime-dir", str(runtime), "init",
                                   "--exchange-host", "exchange.example.org",
                                   "--auth-host", "auth.example.org",
                                   "--objects-host", "objects.example.org"])
            self.assertEqual(code, 1)
            self.assertEqual((runtime / "accounts.json").read_bytes(), original)

    def test_release_receipt_hashes_working_tree_and_untracked_example(self):
        with tempfile.TemporaryDirectory() as temporary:
            instance = object.__new__(stack.Stack)
            instance.runtime = Path(temporary)
            instance.compose = mock.Mock(side_effect=[
                mock.Mock(stdout="[]"),
                mock.Mock(stdout="example-dependency==1.0\\n"),
            ])
            instance.record_release()
            receipt = stack.load_json(instance.runtime / "release.json")
            self.assertIn("examples/first_federation/stack.py", receipt["source_files"])
            self.assertEqual(len(receipt["source_tree_sha256"]), 64)
            self.assertEqual(receipt["source_revision"], receipt["source_revision"].strip())
            self.assertNotIn(chr(0), "".join(receipt["source_files"]))

    def test_missing_python_default_ca_uses_installed_os_bundle(self):
        installed = stack.system_ca_file()
        with mock.patch.dict(os.environ, {"SSL_CERT_FILE": ""}), \
                mock.patch.object(stack.ssl, "get_default_verify_paths",
                                  return_value=mock.Mock(cafile=None)):
            selected = stack.system_ca_file()
            self.assertTrue(selected.is_file())
            stack.ssl.create_default_context(cafile=str(selected))
            self.assertEqual(selected.read_bytes(), installed.read_bytes())

    def test_missing_ca_fails_without_partial_private_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "operator"
            with mock.patch.object(stack, "system_ca_file",
                                   side_effect=ValueError("No usable OS CA bundle")), \
                    contextlib.redirect_stderr(io.StringIO()):
                result = stack.main([
                    "--runtime-dir", str(runtime), "init",
                    "--exchange-host", "exchange.example.org",
                    "--auth-host", "auth.example.org",
                    "--objects-host", "objects.example.org",
                ])
            self.assertEqual(result, 1)
            self.assertFalse(runtime.exists())

    def test_fresh_realm_explicitly_supplies_native_subject_scope(self):
        accounts = {"accounts": {name: {"password": "not-a-real-password"} for name in stack.ACCOUNTS}}
        scopes = {item["name"]: item for item in stack.realm_document(accounts, 300)["clientScopes"]}
        self.assertEqual(scopes["basic"]["protocolMappers"][0]["protocolMapper"], "oidc-sub-mapper")
        self.assertEqual(scopes["basic"]["protocolMappers"][0]["config"]["access.token.claim"], "true")

    def test_existing_realm_scope_reconciliation_is_idempotent(self):
        accounts = {"accounts": {name: {"password": "not-a-real-password"} for name in stack.ACCOUNTS}}
        desired = stack.realm_document(accounts, 300)["clientScopes"]
        root = "https://auth.example.org/admin/realms/hf2l"
        scopes = {"exchange-id": {"name": "exchange", "mappers": []}}
        assignments = set()
        created_scopes = []

        def http(url, *, token=None, data=None, method=None):
            method = method or ("POST" if data is not None else "GET")
            relative = url.removeprefix(root)
            if relative.startswith("/clients/") and method == "PUT":
                assignments.add(relative.rsplit("/", 1)[-1])
                return None
            parts = relative.strip("/").split("/")
            if len(parts) == 1:
                if method == "GET":
                    return [{"id": identifier, "name": value["name"]}
                            for identifier, value in scopes.items()]
                identifier = data["name"] + "-id"
                scopes[identifier] = {
                    "name": data["name"],
                    "mappers": [dict(value, id="subject-id")
                                for value in data.get("protocolMappers", [])],
                }
                created_scopes.append(data["name"])
                return None
            scope = scopes[parts[1]]
            if len(parts) == 2 and method == "PUT":
                scope["name"] = data["name"]
                return None
            if len(parts) == 4:
                if method == "GET":
                    return scope["mappers"]
                scope["mappers"].append(dict(data, id=data["name"] + "-id"))
                return None
            if len(parts) == 5 and method == "PUT":
                scope["mappers"] = [dict(data) if item["id"] == parts[-1] else item
                                    for item in scope["mappers"]]
                return None
            raise AssertionError((relative, method))

        instance = object.__new__(stack.Stack)
        instance.http = http
        instance.reconcile_scopes(root, "unused-private-token", "client-id", desired)
        instance.reconcile_scopes(root, "unused-private-token", "client-id", desired)
        self.assertEqual(created_scopes, ["basic"])
        self.assertEqual(assignments, {"basic-id", "exchange-id"})
        self.assertEqual(len(scopes["basic-id"]["mappers"]), 1)
        self.assertEqual(scopes["basic-id"]["mappers"][0]["protocolMapper"], "oidc-sub-mapper")
        self.assertEqual(scopes["exchange-id"]["mappers"][0]["config"]["included.custom.audience"], "exchange")

    def test_reset_needs_explicit_confirmation_before_mutating(self):
        instance = object.__new__(stack.Stack)
        instance.runtime = Path("/unused/operator")
        instance.compose = mock.Mock()
        with self.assertRaisesRegex(ValueError, "confirm-delete-data"):
            instance.reset(False)
        instance.compose.assert_not_called()

    def test_domain_rejects_urls_paths_ips_and_interpolation(self):
        for value in ("http://example.org", "127.0.0.1", "host", "a..org",
                      "a.example.org/path", "$OTHER.example.org", "-host.example.org"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                stack.validate_host(value)

    def test_bootstrap_uses_actual_issuer_subject_principal(self):
        issuer = "https://auth.example.org/realms/hf2l"
        actual = "17966338-bc66-47f0-9f78-3f397c656539"
        self.assertEqual(stack.principal_id(issuer, actual),
                         __import__("hashlib").sha256(
                             json.dumps([issuer, actual], separators=(",", ":")).encode()
                         ).hexdigest())
        self.assertNotEqual(stack.principal_id(issuer, actual),
                            stack.principal_id(issuer, "alice"))


if __name__ == "__main__":
    unittest.main()
