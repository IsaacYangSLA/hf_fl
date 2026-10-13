"""Bounded manager shutdown settings prevent open streams blocking restarts."""
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from hf2l_jobs.config import OIDCSettings, Settings
from hf2l_jobs.composition import ConfigurationError, _uvicorn


class ManagerShutdownSettingsTests(unittest.TestCase):
    def test_environment_default_override_and_alias_conflict(self):
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(Settings.from_env("database").graceful_shutdown_timeout_seconds, 15)
        for prefix in ("HF2L_JOBS_", "JOBS_"):
            with self.subTest(prefix=prefix), patch.dict("os.environ", {
                    prefix + "GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS": "21"}, clear=True):
                self.assertEqual(Settings.from_env("database").graceful_shutdown_timeout_seconds, 21)
        with patch.dict("os.environ", {
                "HF2L_JOBS_GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS": "15",
                "JOBS_GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS": "21"}, clear=True):
            with self.assertRaisesRegex(ValueError, "Conflicting"):
                Settings.from_env("database")

    def test_invalid_timeouts_cannot_restore_unbounded_shutdown(self):
        for value in (None, True, False, 0, -1, 61, 1.5, "15"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                replace(Settings(), graceful_shutdown_timeout_seconds=value).validate("database")
        for value in ("0", "61", "none", "1.5"):
            with self.subTest(environment=value), patch.dict("os.environ", {
                    "HF2L_JOBS_GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS": value}, clear=True):
                with self.assertRaises(ValueError):
                    Settings.from_env("database")

    def test_server_default_and_trusted_service_override_are_forwarded(self):
        settings = Settings(oidc=OIDCSettings(allow_local_http=True),
                            graceful_shutdown_timeout_seconds=21)
        arguments = SimpleNamespace(host=None, port=None)
        app = Mock()
        for service, expected in (({}, 21), ({"graceful_shutdown_timeout_seconds": 4}, 4)):
            with self.subTest(service=service), patch("uvicorn.run") as serve:
                _uvicorn(app, replace(settings, extra={"service": service}), arguments)
                self.assertEqual(serve.call_args.kwargs["timeout_graceful_shutdown"], expected)
                self.assertFalse(serve.call_args.kwargs["proxy_headers"])

    def test_invalid_service_override_fails_before_starting_server(self):
        settings = Settings(oidc=OIDCSettings(allow_local_http=True))
        arguments = SimpleNamespace(host=None, port=None)
        for value in (None, True, 0, 61, "15"):
            with self.subTest(value=value), patch("uvicorn.run") as serve:
                with self.assertRaises(ConfigurationError):
                    _uvicorn(Mock(), replace(settings, extra={
                        "service": {"graceful_shutdown_timeout_seconds": value}}), arguments)
                serve.assert_not_called()


if __name__ == "__main__":
    unittest.main()
