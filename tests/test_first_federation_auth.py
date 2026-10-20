"""Focused tests for the example's credential boundary; no services required."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

MODULE = Path(__file__).resolve().parents[1] / "examples/first_federation/auth.py"
SPEC = importlib.util.spec_from_file_location("first_federation_auth", MODULE)
auth = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(auth)


class AuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.key.public_key()))
        cls.jwk.update(kid="test-key", use="sig", alg="RS256")
        cls.issuer = "https://auth.example.test/realms/hf2l"
        cls.jwks = cls.issuer + "/protocol/openid-connect/certs"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.profile = Path(self.temp.name) / "actor"
        self.profile.mkdir(mode=0o700)

    def token(self, **updates):
        now = int(time.time())
        claims = dict(iss=self.issuer, sub="actual-user-id", aud="exchange",
                      scope="openid exchange", iat=now, exp=now + 300)
        claims.update(updates)
        return jwt.encode(claims, self.key, algorithm="RS256",
                          headers={"typ": "at+jwt", "kid": "test-key"})

    def state(self):
        return dict(issuer=self.issuer, client_id="hf2l-cli", jwks_uri=self.jwks,
                    token_endpoint=self.issuer + "/protocol/openid-connect/token",
                    access_token=self.token(), refresh_token="refresh-secret",
                    subject="actual-user-id", issued_at=time.time(), expires_at=time.time() + 300)

    def jwks_response(self):
        return patch.object(auth, "request_json", return_value={"keys": [self.jwk]})

    def test_valid_signature_and_actual_principal(self):
        with self.jwks_response():
            state = self.state()
            claims = auth.validate_token(state["access_token"], self.issuer, self.jwks)
            result = auth.identity(state)
        self.assertEqual("actual-user-id", claims["sub"])
        self.assertEqual("actual-user-id", result["subject"])
        self.assertEqual(self.issuer, result["issuer"])
        self.assertEqual(64, len(result["principal_id"]))
        self.assertNotIn("access_token", result)

    def test_rejects_claim_and_signature_failures(self):
        failures = [
            self.token(aud="other"), self.token(iss="https://other.test/realm"),
            self.token(scope="openid"), self.token(sub=""), self.token(sub=4),
            self.token(exp=int(time.time()) - 5), self.token(iat=int(time.time()) + 90),
            self.token(exp=True), self.token(iat=False),
        ]
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        failures.append(jwt.encode(dict(iss=self.issuer, aud="exchange", sub="x",
                                       scope="exchange", iat=int(time.time()),
                                       exp=int(time.time()) + 100), other, algorithm="RS256",
                                   headers={"typ": "at+jwt", "kid": "test-key"}))
        with self.jwks_response():
            for token in failures:
                with self.subTest(token_kind=failures.index(token)):
                    with self.assertRaises(auth.AuthError):
                        auth.validate_token(token, self.issuer, self.jwks)

    def test_claim_diagnostic_names_failure_without_exposing_token_values(self):
        now = int(time.time())
        claims = dict(iss=self.issuer, aud="exchange", scope="exchange", iat=now,
                      exp=now + 100, private_note="never-print-this-value")
        token = jwt.encode(claims, self.key, algorithm="RS256",
                           headers={"typ": "at+jwt", "kid": "test-key"})
        with self.jwks_response(), self.assertRaises(auth.AuthError) as caught:
            auth.validate_token(token, self.issuer, self.jwks)
        self.assertEqual("Access token is missing the sub claim.", str(caught.exception))
        self.assertNotIn(token, str(caught.exception))
        self.assertNotIn(claims["private_note"], str(caught.exception))

    def test_rejects_non_access_header(self):
        token = jwt.encode({"sub": "x"}, self.key, algorithm="RS256",
                           headers={"typ": "JWT", "kid": "test-key"})
        with self.assertRaises(auth.AuthError):
            auth.validate_token(token, self.issuer, self.jwks)

    def test_rejects_ambiguous_or_missing_jwks_key(self):
        for keys in ([], [self.jwk, self.jwk]):
            with patch.object(auth, "request_json", return_value={"keys": keys}):
                with self.assertRaises(auth.AuthError):
                    auth.validate_token(self.token(), self.issuer, self.jwks)

    def test_discovery_rejects_issuer_mismatch_and_cross_origin(self):
        metadata = dict(issuer=self.issuer, token_endpoint=self.issuer + "/token",
                        jwks_uri=self.jwks, device_authorization_endpoint=self.issuer + "/device")
        for updates in ({"issuer": "https://other.test"},
                        {"token_endpoint": "http://auth.example.test/token"},
                        {"jwks_uri": "https://other.test/keys"}):
            with patch.object(auth, "request_json", return_value=dict(metadata, **updates)):
                with self.assertRaises(auth.AuthError):
                    auth.discovery(self.issuer)

    def test_https_rejects_credentials_fragment_and_http(self):
        for value in ("http://example.test", "https://user:secret@example.test",
                      "https://example.test/#fragment"):
            with self.assertRaises(auth.AuthError):
                auth.https_url(value)

    def test_atomic_private_replaces_without_exposing_partial_token(self):
        target = self.profile / "access.token"
        target.write_text("old")
        old_inode = target.stat().st_ino
        auth.atomic_private(target, "new-token\n")
        self.assertEqual("new-token\n", target.read_text())
        self.assertEqual(0o600, stat.S_IMODE(target.stat().st_mode))
        self.assertNotEqual(old_inode, target.stat().st_ino)
        self.assertEqual(["access.token"], [p.name for p in self.profile.iterdir()])

    def test_symlink_target_does_not_overwrite_foreign_file(self):
        outside = Path(self.temp.name) / "outside"
        outside.write_text("preserved")
        (self.profile / "access.token").symlink_to(outside)
        auth.atomic_private(self.profile / "access.token", "new")
        self.assertEqual("preserved", outside.read_text())
        self.assertFalse((self.profile / "access.token").is_symlink())

    def test_profile_lock_prevents_concurrent_commands_and_symlink_profiles(self):
        with auth.profile_lock(self.profile):
            with self.assertRaises(auth.AuthError):
                with auth.profile_lock(self.profile):
                    self.fail("lock was shared")
        alias = Path(self.temp.name) / "alias"
        alias.symlink_to(self.profile, target_is_directory=True)
        with self.assertRaises(auth.AuthError):
            with auth.profile_lock(alias):
                self.fail("symlink was followed")

    def test_private_state_rejects_permissions_and_symlink(self):
        path = self.profile / "credentials.json"
        path.write_text(json.dumps(self.state()))
        path.chmod(0o644)
        with self.assertRaises(auth.AuthError):
            auth.load_state(self.profile)
        path.chmod(0o600)
        self.assertEqual(self.issuer, auth.load_state(self.profile)["issuer"])
        path.unlink()
        outside = Path(self.temp.name) / "external"
        outside.write_text("{}")
        path.symlink_to(outside)
        with self.assertRaises(auth.AuthError):
            auth.load_state(self.profile)

    def test_refresh_rotates_both_private_files_and_keeps_subject(self):
        state = self.state()
        token = self.token()
        response = dict(token_type="Bearer", access_token=token, refresh_token="new-refresh")
        with self.jwks_response():
            updated = auth.accept_tokens(self.profile, state, response)
        self.assertEqual("new-refresh", updated["refresh_token"])
        self.assertEqual(token, (self.profile / "access.token").read_text().strip())
        self.assertEqual(updated, auth.load_state(self.profile))
        response["access_token"] = self.token(sub="foreign-user")
        with self.jwks_response(), self.assertRaises(auth.AuthError):
            auth.accept_tokens(self.profile, state, response)
        self.assertEqual("actual-user-id", auth.load_state(self.profile)["subject"])

    def test_token_precedence_is_managed_and_explicit_overrides_rejected(self):
        with patch.dict(os.environ, {"EXCHANGE_TOKEN": "untrusted",
                                    "EXCHANGE_TOKEN_FILE": "/untrusted", "OTHER": "kept"}):
            env = auth.command_environment(self.profile, ["hf2l", "download"])
        self.assertNotIn("EXCHANGE_TOKEN", env)
        self.assertEqual(str(self.profile / "access.token"), env["EXCHANGE_TOKEN_FILE"])
        self.assertEqual("kept", env["OTHER"])
        for override in ("--token", "--token=x", "--token-file", "--token-file=x",
                         "EXCHANGE_TOKEN=x", "EXCHANGE_TOKEN_FILE=x"):
            with self.assertRaises(auth.AuthError):
                auth.command_environment(self.profile, ["hf2l", override])

    def test_actual_hf2l_parser_token_abbreviations_cannot_bypass_runner(self):
        from hf2l.client_download import parse_args
        required = ["--repo-id", "project", "--base-revision", "base",
                    "--work-dir", "/unused", "--backend", "exchange"]
        for option in ("--t", "--to", "--tok", "--toke", "--token"):
            for spelling in ([option, "static-secret"], [option + "=static-secret"]):
                with self.subTest(option=spelling):
                    parsed = parse_args(required + spelling)
                    self.assertEqual("static-secret", parsed.token)
                    with self.assertRaises(auth.AuthError):
                        auth.command_environment(self.profile, ["hf2l", "client-download",
                                                                *required, *spelling])
        for option in ("--token-", "--token-f", "--token-fi", "--token-fil", "--token-file"):
            for spelling in (option, option + "=private-file"):
                with self.subTest(option=spelling), self.assertRaises(auth.AuthError):
                    auth.command_environment(self.profile, ["helper", spelling])

    def test_unrelated_trainer_options_remain_usable(self):
        environment = auth.command_environment(
            self.profile, ["trainer", "--tokens", "128", "--tokenizer=local",
                           "--token-cache", "/local", "--temperature=0.7"])
        self.assertEqual(str(self.profile / "access.token"), environment["EXCHANGE_TOKEN_FILE"])

    def device_metadata(self):
        return dict(issuer=self.issuer, token_endpoint=self.issuer + "/token",
                    jwks_uri=self.jwks, device_authorization_endpoint=self.issuer + "/device")

    def test_device_poll_pending_and_slow_down_then_success(self):
        device = dict(device_code="device-secret", user_code="ABCD", expires_in=300,
                      interval=1, verification_uri=self.issuer + "/device")
        metadata = self.device_metadata()
        responses = [device, auth.OAuthError("authorization_pending"),
                     auth.OAuthError("slow_down"), {"token_type": "Bearer"}]
        with patch.object(auth, "discovery", return_value=metadata), \
                patch.object(auth, "request_json", side_effect=responses), \
                patch.object(auth.time, "sleep") as sleep, \
                patch.object(auth, "accept_tokens", return_value=self.state()), \
                patch.object(auth, "identity", return_value={"subject": "actual-user-id"}), \
                patch("builtins.print") as output:
            auth.login(self.profile, self.issuer, "hf2l-cli")
        self.assertEqual([1, 1, 6], [call.args[0] for call in sleep.call_args_list])
        printed = " ".join(str(call.args) for call in output.call_args_list)
        self.assertNotIn("device-secret", printed)
        self.assertNotIn("refresh-secret", printed)

    def test_device_denial_stops_without_creating_credentials(self):
        device = dict(device_code="secret", user_code="ABCD", expires_in=300,
                      interval=1, verification_uri=self.issuer + "/device")
        with patch.object(auth, "discovery", return_value=self.device_metadata()), \
                patch.object(auth, "request_json", side_effect=[device, auth.OAuthError("access_denied")]), \
                patch.object(auth.time, "sleep"), patch("builtins.print"), \
                self.assertRaises(auth.OAuthError):
            auth.login(self.profile, self.issuer, "hf2l-cli")
        self.assertFalse((self.profile / "credentials.json").exists())

    def test_device_expiry_is_bounded(self):
        device = dict(device_code="secret", user_code="ABCD", expires_in=1,
                      interval=1, verification_uri=self.issuer + "/device")
        with patch.object(auth, "discovery", return_value=self.device_metadata()), \
                patch.object(auth, "request_json", return_value=device) as request, \
                patch("builtins.print"), self.assertRaises(auth.AuthError):
            auth.login(self.profile, self.issuer, "hf2l-cli")
        self.assertEqual(1, request.call_count)

    def test_renewal_margin_supports_short_lived_tokens(self):
        self.assertEqual(970, auth.renewal_at(dict(issued_at=940, expires_at=1000)))
        self.assertEqual(940, auth.renewal_at(dict(issued_at=700, expires_at=1000)))

    def test_run_refreshes_before_child_and_returns_exit_status(self):
        state = self.state()
        output = Path(self.temp.name) / "environment.json"
        script = ("import os,json,pathlib,sys;pathlib.Path(sys.argv[1]).write_text("
                  "json.dumps({k:v for k,v in os.environ.items() if k.startswith('EXCHANGE_TOKEN')}));"
                  "sys.exit(7)")
        with patch.object(auth, "load_state", return_value=state), \
                patch.object(auth, "refresh", return_value=state) as refresh, \
                patch.dict(os.environ, {"EXCHANGE_TOKEN": "inherited-secret"}):
            result = auth.run(self.profile, [sys.executable, "-c", script, str(output)])
        self.assertEqual(7, result)
        self.assertEqual(1, refresh.call_count)
        self.assertEqual({"EXCHANGE_TOKEN_FILE": str(self.profile / "access.token")},
                         json.loads(output.read_text()))

    def test_run_refuses_child_when_initial_refresh_fails(self):
        with patch.object(auth, "load_state", return_value=self.state()), \
                patch.object(auth, "refresh", side_effect=auth.AuthError("expired")), \
                patch.object(auth.subprocess, "Popen") as child, self.assertRaises(auth.AuthError):
            auth.run(self.profile, ["unused"])
        child.assert_not_called()

    def test_run_stops_child_when_renewal_cannot_outlive_expiry(self):
        state = dict(self.state(), issued_at=0, expires_at=time.time() + 3)
        child = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"],
                                 start_new_session=True)
        self.addCleanup(lambda: auth.stop_child(child))
        with patch.object(auth, "load_state", return_value=state), \
                patch.object(auth, "refresh", side_effect=[state, auth.AuthError("offline"),
                                                         auth.AuthError("offline")]), \
                patch.object(auth.subprocess, "Popen", return_value=child), \
                patch("builtins.print"), self.assertRaises(auth.AuthError):
            auth.run(self.profile, ["unused"])
        self.assertIsNotNone(child.poll())


if __name__ == "__main__":
    unittest.main()
