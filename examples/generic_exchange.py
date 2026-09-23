"""Upload, discover, download and coordinate document processing without ML dependencies.

Install packages/exchange in a virtualenv, start the v2 API and worker, then run:
  EXCHANGE_TOKEN=... python examples/generic_exchange.py \
    --endpoint https://exchange.example --input report.txt --work-dir ./document-run
The token needs permission to create a space (or use --space with admin/publisher roles).
Reuse --work-dir to recover lost responses; do not share it across concurrent jobs.
"""
import argparse
import hashlib
import os
from pathlib import Path

from hf2l_exchange.client import ExchangeClient, ExchangeError
from hf2l_exchange.client_state import StateRepository


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--space", help="Use an existing generic space")
    parser.add_argument("--allow-local-http", action="store_true")
    args = parser.parse_args()
    work = args.work_dir
    work.mkdir(parents=True, exist_ok=True)
    repository = StateRepository(work / "setup.json")
    setup = repository.begin("document-example", [args.endpoint, args.space, str(args.input.resolve())])
    with ExchangeClient(args.endpoint, os.environ["EXCHANGE_TOKEN"], allow_local_http=args.allow_local_http) as client:
        space = args.space or client.create_space("Document processing", idempotency_key=setup["key"]).id
        schema = {"type": "object", "properties": {"title": {"type": "string"}},
                  "required": ["title"], "additionalProperties": False}
        document_type = client.register_type(space, "document", schema,
                                              idempotency_key=setup["key"] + "-type")
        source = client.put_record(space, kind="document", schema_revision_id=document_type.id,
                                  metadata={"title": args.input.name}, files={"source.txt": args.input},
                                  state_path=work / "upload-source.json")
        reference_name = "processed-" + hashlib.sha256(setup["key"].encode()).hexdigest()[:12]
        try:
            base = client.set_ref(space, reference_name, source.id, idempotency_key=setup["key"] + "-ref")
        except ExchangeError as exc:
            if exc.status != 412:
                raise
            base = client.resolve(space, reference_name)
        attempt = client.acquire(space, reference=base, input_ids=[source.id], state_path=work / "acquisition.json")
        if attempt.state == "completed":
            print(f"Completed record: {attempt.result_record_id}")
            return
        # Discovery uses only generic types and immutable published records.
        assert any(record.id == source.id for record in client.records(space, kind="document"))
        local = client.download_attachment(space, source.id, source.attachments[0], work / "downloaded.txt")
        transformed = work / "processed.txt"
        transformed.write_text(local.read_text(encoding="utf-8").upper(), encoding="utf-8")
        result = client.put_record(space, kind="document", schema_revision_id=document_type.id,
                                  metadata={"title": "Processed " + args.input.name}, files={"result.txt": transformed},
                                  state_path=work / "upload-result.json")
        outcome = client.complete(space, attempt, result.id, state_path=work / "completion.json")
        print(f"Space: {space}\nReference: {reference_name}\nCompleted record: {outcome.result_record_id}")


if __name__ == "__main__":
    main()
