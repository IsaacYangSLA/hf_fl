"""Small guardrail tests for the real-service example verifier."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "first_federation_verify", Path(__file__).resolve().parents[1] / "verify.py")
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)


class VerifierGuardrails(unittest.TestCase):
    def test_credentials_do_not_cross_actor_environment(self):
        with patch.dict(os.environ, {
            "EXCHANGE_TOKEN": "previous-actor-token",
            "EXCHANGE_TOKEN_FILE": "/previous/actor",
            "AWS_ACCESS_KEY_ID": "host-key", "AWS_SECRET_ACCESS_KEY": "host-secret",
            "HTTP_PROXY": "http://private-proxy", "PYTHONPATH": "/host/python"}):
            environment = verify.clean_environment("/private/alice", "/public/ca.crt", "https://exchange.test")
        for name in ["EXCHANGE_TOKEN", "EXCHANGE_TOKEN_FILE", "AWS_ACCESS_KEY_ID",
                     "AWS_SECRET_ACCESS_KEY", "HTTP_PROXY", "PYTHONPATH"]:
            self.assertNotIn(name, environment)
        self.assertEqual(environment["HOME"], "/private/alice")
        self.assertEqual(environment["SSL_CERT_FILE"], "/public/ca.crt")

    def test_atomic_private_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            verify.save_json(path, {"space_id": "one"})
            verify.save_json(path, {"space_id": "two"})
            self.assertEqual(json.loads(path.read_text())["space_id"], "two")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(Path(temporary).iterdir()), [path])

    def test_private_directory_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "link"
            path.symlink_to(temporary, target_is_directory=True)
            with self.assertRaises(ValueError):
                verify.private_directory(path)

    def test_secret_and_unknown_jwt_redaction(self):
        value = verify.redact("password=sensitive eyJhbGciOiJSUzI1NiJ9.abc.def", ["sensitive"])
        self.assertNotIn("sensitive", value)
        self.assertNotIn("eyJ", value)

    def test_json_extraction_accepts_human_cli_prefixes(self):
        self.assertEqual(verify.last_json('downloaded=ok\n{"status":"published"}\n')["status"], "published")
        with self.assertRaises(ValueError):
            verify.last_json("operation failed")

    def test_denial_does_not_treat_outages_as_auth_success(self):
        class Failure(Exception):
            def __init__(self, status):
                self.status = status
        def failure(status):
            def call():
                raise Failure(status)
            return call
        self.assertEqual(verify.expect_denied(failure(403)), 403)
        with self.assertRaises(Failure):
            verify.expect_denied(failure(503))
        with self.assertRaises(AssertionError):
            verify.expect_denied(lambda: None)

    def test_weighted_oracle_rejects_uniform_aggregation(self):
        import numpy as np
        from safetensors.numpy import save_file
        with tempfile.TemporaryDirectory() as temporary:
            paths = [Path(temporary) / name for name in ("aggregate", "alice", "bob")]
            for path in paths:
                path.mkdir()
            for path, value in zip(paths, (6.0, 0.0, 10.0)):
                save_file({"weight": np.array([value], dtype=np.float32)}, str(path / "model.safetensors"))
            self.assertEqual(verify.weighted_checkpoint(*paths)["weight"], 0.0)
            save_file({"weight": np.array([5.0], dtype=np.float32)}, str(paths[0] / "model.safetensors"))
            with self.assertRaises(AssertionError):
                verify.weighted_checkpoint(*paths)

    def test_runtime_inside_source_is_rejected_before_commands(self):
        arguments = verify.parse_args(["--runtime-dir", str(verify.ROOT / "private")])
        with self.assertRaisesRegex(ValueError, "outside"):
            verify.Verification(arguments)

    def test_expected_cli_rejection_cannot_pass_on_service_outage(self):
        with tempfile.TemporaryDirectory() as temporary:
            verification = verify.Verification.__new__(verify.Verification)
            verification.evidence = Path(temporary)
            verification.secrets = []
            verification.stack_env = {}
            outage = verify.subprocess.CompletedProcess(["hf2l"], 1, "error: connection_failed")
            with patch.object(verify.subprocess, "run", return_value=outage):
                with self.assertRaisesRegex(AssertionError, "different reason"):
                    verification.command(["hf2l"], fail=True,
                                         expected_error="Model configuration changed")
            rejection = verify.subprocess.CompletedProcess(["hf2l"], 1,
                                                           "error: Model configuration changed")
            with patch.object(verify.subprocess, "run", return_value=rejection):
                verification.command(["hf2l"], fail=True,
                                     expected_error="Model configuration changed")

    def test_venv_python_symlink_preserves_venv_entrypoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            python = Path(temporary) / "venv" / "bin" / "python"
            python.parent.mkdir(parents=True)
            python.symlink_to(verify.sys.executable)
            arguments = verify.parse_args(["--runtime-dir", str(Path(temporary) / "runtime"),
                                           "--python", str(python)])
            with patch.object(verify.Verification, "command", return_value="source-revision"):
                verification = verify.Verification(arguments)
            self.assertEqual(verification.python, str(python))
            self.assertEqual(verification.hf2l, str(python.parent / "hf2l"))

    def test_stages_are_explicit(self):
        arguments = verify.parse_args(["--runtime-dir", "/private/qualification", "--stage", "restart"])
        self.assertEqual(arguments.stage, "restart")
        self.assertEqual(arguments.https_port, 8443)


if __name__ == "__main__":
    unittest.main()
