"""Generated contracts stay tied to HTTP, lifecycle, and configuration behavior."""
from __future__ import annotations

import ast
from contextlib import redirect_stdout
import inspect
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from typing import get_args
from unittest.mock import patch

from hf2l_exchange import application, config, domain, transfers
from hf2l_exchange.api import Role as HTTPRole
from hf2l_exchange.cli import main
from hf2l_exchange.contracts import (environment_contract, error_catalog, openapi_contract,
                                     render_contracts)
from hf2l_exchange.models import Record, TransferAttempt
from hf2l_exchange.vocabulary import (RECORD_STATES, ROLES, TERMINAL_RECORD_STATES,
                                      TRANSFER_STATES, RecordState, Role, TransferState)

ROOT = Path(__file__).resolve().parents[3]


class ContractTests(unittest.TestCase):
    def test_generated_files_match_actual_implementation(self):
        first = render_contracts()
        self.assertEqual(first, render_contracts())
        for name, expected in first.items():
            self.assertEqual((ROOT / "docs/generated" / name).read_text(encoding="utf-8"), expected,
                             f"Regenerate {name} with hf2l-exchange export-contract")

    def test_export_needs_no_environment_database_or_provider(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {}, clear=True), \
                patch.object(config.Settings, "from_env", side_effect=AssertionError("environment accessed")), \
                redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["export-contract", "--output-dir", temporary]), 0)
            self.assertEqual(len(list(Path(temporary).iterdir())), 3)
            self.assertIn("exchange-api.json", output.getvalue())

    def test_openapi_has_current_paths_headers_and_schema_constraints(self):
        schema = openapi_contract()
        self.assertTrue(schema["openapi"].startswith("3."))
        operation = schema["paths"]["/v2/spaces/{space}/refs/{name}"]["put"]
        headers = {item["name"].lower() for item in operation["parameters"] if item["in"] == "header"}
        self.assertTrue({"if-match", "if-none-match", "idempotency-key"}.issubset(headers))
        models = schema["components"]["schemas"]
        self.assertEqual(models["RecordBody"]["properties"]["attachments"]["maxItems"], 256)
        self.assertEqual(models["SpaceBody"]["properties"]["quota_bytes"]["minimum"], 1)
        self.assertEqual(set(models["MemberBody"]["properties"]["roles"]["items"]["enum"]), ROLES)
        self.assertNotIn("/health", schema["paths"])

    def test_error_inventory_preserves_multiple_statuses_and_flags_dynamic_calls(self):
        with tempfile.TemporaryDirectory() as temporary:
            Path(temporary, "sample.py").write_text(
                'raise Error(409, "conflict")\nraise Error(422, "conflict")\n'
                'raise Error(503, "missing" if failed else "unavailable")\n'
                'raise ExchangeError(response.status_code, response.code)\n'
                'raise StorageFailure("provider_down", retryable=True)\n', encoding="utf-8")
            catalog = error_catalog(temporary)
        by_code = {item["code"]: item for item in catalog["errors"]}
        self.assertEqual(by_code["conflict"]["statuses"], [409, 422])
        self.assertEqual(by_code["missing"]["statuses"], [503])
        self.assertEqual(catalog["dynamic_calls"][0]["status_expression"], "response.status_code")
        provider = catalog["storage_failures"][0]
        self.assertNotIn("statuses", provider)
        self.assertEqual(provider["call_sites"][0]["retryable"], "True")

    def test_environment_table_matches_loader_defaults_without_reading_secrets(self):
        with patch.dict(os.environ, {"EXCHANGE_ISSUER": "https://identity.invalid",
                                     "EXCHANGE_JWT_PUBLIC_KEY": "key", "EXCHANGE_S3_BUCKET": "bucket"}, clear=True):
            values = config.Settings.from_env()
        instances = {"Settings": config.Settings(), "DatabaseSettings": values.database,
                     "AuthSettings": config.AuthSettings(), "StorageSettings": config.StorageSettings(),
                     "WorkerSettings": values.worker}
        for row in environment_contract():
            owner, name = row["field"].split(".")
            self.assertEqual(row["default"], getattr(instances[owner], name))
        with patch.dict(os.environ, {"EXCHANGE_S3_SECRET_KEY": "private-never-render",
                                     "AWS_SECRET_ACCESS_KEY": "private-never-render"}):
            self.assertNotIn("private-never-render", json.dumps(render_contracts()))
        rows = {row["variable"]: row for row in environment_contract()}
        self.assertIn("AWS_SECRET_ACCESS_KEY", rows["EXCHANGE_S3_SECRET_KEY"]["notes"])
        self.assertIn("Overrides", rows["EXCHANGE_EVENT_RETENTION_SECONDS"]["notes"])

    def test_vocabulary_matches_allowed_roles_and_lifecycle_values(self):
        self.assertEqual(ROLES, set(get_args(HTTPRole)))
        self.assertEqual(ROLES, application.ROLES)
        self.assertIs(ROLES, domain.ROLES)
        self.assertEqual(TERMINAL_RECORD_STATES, application.TERMINAL)
        self.assertEqual(RECORD_STATES, TERMINAL_RECORD_STATES | {Record.state.default.arg, "published"})
        tree = ast.parse(inspect.getsource(transfers))
        observed = {TransferAttempt.state.default.arg}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            candidate = node.left
            is_state = isinstance(candidate, ast.Name) and candidate.id == "state"
            is_attempt_state = (isinstance(candidate, ast.Attribute) and candidate.attr == "state"
                                and isinstance(candidate.value, ast.Name) and candidate.value.id == "attempt")
            if is_state or is_attempt_state:
                for child in ast.walk(node):
                    if isinstance(child, ast.Constant) and isinstance(child.value, str):
                        observed.add(child.value)
        self.assertEqual(TRANSFER_STATES, observed)
        self.assertEqual(json.loads(json.dumps([Role.READER, RecordState.PUBLISHED, TransferState.VERIFIED])),
                         ["reader", "published", "verified"])


if __name__ == "__main__":
    unittest.main()
