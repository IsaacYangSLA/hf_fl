from __future__ import annotations

import io
import json
import unittest
from unittest.mock import Mock, patch
from urllib.error import URLError

from examples.hf_webhook_relay import application, dispatch


class WebhookRelayTests(unittest.TestCase):
    def setUp(self):
        self.configuration = patch.dict("os.environ", {
            "HF_WEBHOOK_SECRET": "test-secret",
            "GITHUB_DISPATCH_TOKEN": "test-token",
            "GITHUB_REPOSITORY": "owner/code",
            "HF_REPO_ID": "owner/model",
        })
        self.configuration.start()
        self.addCleanup(self.configuration.stop)
        self.payload = {
            "repo": {"name": "owner/model", "type": "model"},
            "event": {"scope": "discussion", "action": "create"},
            "discussion": {"isPullRequest": True, "status": "open"},
        }

    def request(self, payload=None, **overrides):
        body = json.dumps(self.payload if payload is None else payload).encode()
        environ = {
            "PATH_INFO": "/hf-webhook",
            "REQUEST_METHOD": "POST",
            "HTTP_X_WEBHOOK_SECRET": "test-secret",
            "CONTENT_LENGTH": str(len(body)),
            "wsgi.input": io.BytesIO(body),
            **overrides,
        }
        start_response = Mock()
        response = b"".join(application(environ, start_response)).decode()
        return start_response.call_args.args[0], response

    @patch("examples.hf_webhook_relay.dispatch")
    def test_open_and_reopened_prs_dispatch(self, send):
        for action in ("create", "update"):
            self.payload["event"]["action"] = action
            self.assertEqual(self.request()[0], "202 Accepted")
        self.assertEqual(send.call_count, 2)
        send.assert_called_with("owner/code", "test-token")

    @patch("examples.hf_webhook_relay.dispatch")
    def test_updated_pr_ref_dispatches(self, send):
        self.payload["event"] = {"scope": "repo.content", "action": "update"}
        self.payload.pop("discussion")
        self.payload["updatedRefs"] = [{"ref": "refs/pr/5", "newSha": "updated-sha"}]
        self.assertEqual(self.request()[0], "202 Accepted")
        send.assert_called_once()

    @patch("examples.hf_webhook_relay.dispatch")
    def test_aggregate_main_update_does_not_loop(self, send):
        self.payload["event"] = {"scope": "repo.content", "action": "update"}
        self.payload["updatedRefs"] = [{"ref": "refs/heads/main", "newSha": "aggregate-sha"}]
        self.assertEqual(self.request(), ("200 OK", "Ignored\n"))
        send.assert_not_called()

    @patch("examples.hf_webhook_relay.dispatch")
    def test_unrelated_repo_discussion_closed_pr_and_comment_are_ignored(self, send):
        cases = [
            {**self.payload, "repo": {"name": "other/model", "type": "model"}},
            {**self.payload, "repo": {"name": "owner/model", "type": "dataset"}},
            {**self.payload, "discussion": {"isPullRequest": False, "status": "open"}},
            {**self.payload, "discussion": {"isPullRequest": True, "status": "closed"}},
            {**self.payload, "event": {"scope": "discussion.comment", "action": "create"}},
        ]
        for payload in cases:
            with self.subTest(payload=payload):
                self.assertEqual(self.request(payload), ("200 OK", "Ignored\n"))
        send.assert_not_called()

    @patch("examples.hf_webhook_relay.dispatch")
    def test_secret_is_checked_before_dispatch(self, send):
        self.assertEqual(self.request(HTTP_X_WEBHOOK_SECRET="wrong")[0], "403 Forbidden")
        self.assertEqual(self.request(HTTP_X_WEBHOOK_SECRET="")[0], "403 Forbidden")
        send.assert_not_called()

    @patch("examples.hf_webhook_relay.dispatch")
    def test_invalid_requests_do_not_dispatch(self, send):
        cases = [
            ({"PATH_INFO": "/other"}, "404 Not Found"),
            ({"REQUEST_METHOD": "GET"}, "405 Method Not Allowed"),
            ({"CONTENT_LENGTH": ""}, "400 Bad Request"),
            ({"CONTENT_LENGTH": "999999999"}, "413 Content Too Large"),
            ({"wsgi.input": io.BytesIO(b"invalid")}, "400 Bad Request"),
        ]
        for overrides, expected in cases:
            with self.subTest(overrides=overrides):
                self.assertEqual(self.request(**overrides)[0], expected)
        self.assertEqual(self.request([])[0], "400 Bad Request")
        send.assert_not_called()

    @patch("examples.hf_webhook_relay.dispatch", side_effect=URLError("private error"))
    def test_dispatch_failure_returns_retryable_error_without_details(self, send):
        status, body = self.request()
        self.assertEqual(status, "502 Bad Gateway")
        self.assertNotIn("private error", body)
        self.assertNotIn("test-token", body)

    @patch("examples.hf_webhook_relay.urlopen")
    def test_github_request_uses_fixed_event_and_authentication(self, open_url):
        open_url.return_value.__enter__.return_value.status = 204
        dispatch("owner/code", "test-token")
        request = open_url.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.github.com/repos/owner/code/dispatches")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.get_header("Authorization"), "Bearer test-token")
        self.assertEqual(json.loads(request.data), {"event_type": "hf-pr-update"})
        self.assertEqual(open_url.call_args.kwargs["timeout"], 15)


if __name__ == "__main__":
    unittest.main()
