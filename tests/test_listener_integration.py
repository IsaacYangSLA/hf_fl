"""Two real clients follow owner publications through persistent listeners."""

from __future__ import annotations

from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from hf2l.backends.local import LocalStore
from hf2l.fedavg_runner import run_round
from hf2l.listener.client import ClientListener
from hf2l.round.config import RoundConfig
from tests.support.v3_helpers import checkpoint_value, initialize_model, write_checkpoint


ROOT = Path(__file__).resolve().parents[1]
PARTICIPANTS = (("alice", 1), ("bob", 3))


def train_increment(base_dir, output_dir, options):
    """Keep the numerical outcome transparent without a training framework."""
    starting_value = checkpoint_value(base_dir)
    examples = dict(PARTICIPANTS)[options["participant"]]
    write_checkpoint(output_dir, starting_value + examples)
    return {"num_examples": examples, "starting_value": starting_value}


def assert_round(test, result, base, number):
    test.assertEqual(result.status, "published")
    test.assertEqual(result.base.revision, base)
    test.assertEqual(result.round_number, number)
    test.assertEqual(checkpoint_value(result.aggregate_dir), 2.5 * number)
    test.assertEqual(
        {entry["participant"]: entry["coefficient"] for entry in result.eligible},
        {"alice": 0.25, "bob": 0.75},
    )


@unittest.skipUnless(os.name == "posix", "Listener state uses POSIX filesystem locks")
class LocalListenerIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hf2l-listener-integration-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.root = self.directory / "store"
        self.repo = "listened-model"
        self.owner = LocalStore(self.root, "owner")
        self.addCleanup(self.owner.close)
        initial = initialize_model(self.directory / "initial", "local")
        self.base = self.owner.initialize_repository(self.repo, initial, private=True).revision
        self.processes = {}
        self.logs = {}
        self.plugin = self.directory / "train.py"
        self.plugin.write_text(
            "import shutil\n"
            "from safetensors.numpy import load_file, save_file\n"
            "\n"
            "def train_model(base_dir, output_dir, options):\n"
            "    values = load_file(base_dir / 'model.safetensors')\n"
            "    starting = float(values['weight'][0])\n"
            "    examples = {'alice': 1, 'bob': 3}[options['participant']]\n"
            "    values['weight'] += examples\n"
            "    output_dir.mkdir()\n"
            "    save_file(values, output_dir / 'model.safetensors')\n"
            "    shutil.copyfile(base_dir / 'config.json', output_dir / 'config.json')\n"
            "    return {'num_examples': examples, 'starting_value': starting}\n",
            encoding="utf-8",
        )

    @staticmethod
    def stop_process(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)

    def start_listener(self, participant):
        log_path = self.directory / (participant + ".log")
        output = log_path.open("w", encoding="utf-8")
        self.addCleanup(output.close)
        process = subprocess.Popen(
            [sys.executable, "-m", "hf2l.cli", "listen", "--backend", "local",
             "--endpoint", str(self.root), "--local-principal", participant,
             "--repo-id", self.repo, "--participant", participant,
             "--state-dir", str(self.directory / participant), "--plugin", str(self.plugin),
             "--poll-interval", "0.05", "--max-backoff", "0.1", "--max-rounds", "2"],
            cwd=ROOT, stdout=output, stderr=subprocess.STDOUT,
        )
        self.addCleanup(self.stop_process, process)
        self.processes[participant] = process
        self.logs[participant] = log_path

    def await_first_round_and_idle(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            ready = True
            for participant, process in self.processes.items():
                diagnostic = self.logs[participant].read_text(encoding="utf-8")
                self.assertIsNone(process.poll(), diagnostic)
                state_path = self.directory / participant / "state.json"
                if not state_path.exists():
                    ready = False
                    continue
                state = json.loads(state_path.read_text(encoding="utf-8"))
                ready = ready and state["completed_round"] == 0 and '"event": "idle"' in diagnostic
            if ready:
                return
            time.sleep(0.02)
        self.fail("Listeners did not submit and become idle:\n" + "\n".join(
            path.read_text(encoding="utf-8") for path in self.logs.values()))

    def test_two_client_processes_follow_owner_publication_and_submit_next_round(self):
        for participant, _ in PARTICIPANTS:
            self.start_listener(participant)
        self.await_first_round_and_idle()
        self.assertEqual(self.owner.resolve_revision(self.repo, "main"), self.base)

        first = run_round(self.owner, RoundConfig(
            repo_id=self.repo, output_dir=self.directory / "round-one", publish=True,
            expected_base_revision=self.base, require_concurrent_publication=True,
            array_backend="numpy"))
        assert_round(self, first, self.base, 1)
        next_base = first.publication.revision

        # Both already-running processes must observe the owner publication;
        # no per-client restart or manual next-round descriptor is involved.
        for participant, process in self.processes.items():
            process.wait(timeout=30)
            diagnostic = self.logs[participant].read_text(encoding="utf-8")
            self.assertEqual(process.returncode, 0, diagnostic)
            events = [json.loads(line) for line in diagnostic.splitlines()]
            self.assertEqual(sum(event["event"] == "submitted" for event in events), 2)
            state = json.loads((self.directory / participant / "state.json").read_text())
            self.assertEqual(state["completed_round"], 1)
            self.assertIsNone(state["active"])
            self.assertEqual(set(state["jobs"]), {self.base, next_base})
            self.assertEqual({job["status"] for job in state["jobs"].values()}, {"submitted"})

        second = run_round(self.owner, RoundConfig(
            repo_id=self.repo, output_dir=self.directory / "round-two", publish=True,
            expected_base_revision=next_base, require_concurrent_publication=True,
            array_backend="numpy"))
        assert_round(self, second, next_base, 2)
        candidates, _ = self.owner.discover_submissions(self.repo)
        self.assertEqual(len(candidates), 4)
        self.assertEqual(self.owner.resolve_revision(self.repo, "main"), second.publication.revision)


# Load only the shared resource fixture, avoiding importing/collecting the
# existing end-to-end test classes a second time.
_exchange_available = all(importlib.util.find_spec(name) is not None for name in (
    "boto3", "moto", "sqlalchemy", "jwt", "fastapi", "hf2l_exchange"))
if not _exchange_available and os.environ.get("EXCHANGE_REQUIRE_TESTS") == "1":
    raise ImportError("Listener Exchange integration requires the exchange service/test dependencies")
if _exchange_available:
    _spec = importlib.util.spec_from_file_location(
        "listener_exchange_test_support", ROOT / "packages/exchange/tests/support.py")
    _support = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_support)
    _ExchangeTestCase = _support.ExchangeTestCase
else:
    _ExchangeTestCase = unittest.TestCase


@unittest.skipUnless(_exchange_available and os.name == "posix",
                     "Exchange integration dependencies and POSIX locks are required")
class ExchangeListenerIntegrationTests(_ExchangeTestCase):
    def sdk(self, subject):
        from hf2l_exchange.client import ExchangeClient
        from hf2l_exchange.worker import tick

        client = ExchangeClient(
            "http://127.0.0.1", self.auth(subject)["Authorization"].split(" ", 1)[1],
            http=self.client, allow_local_http=True, sleep=lambda _: tick(self.transfers))
        self.addCleanup(client.close)
        return client

    def listener(self, store, participant):
        return ClientListener(
            store, repo_id=self.federation, participant=participant,
            state_dir=self.directory / ("listener-" + participant),
            source_id="http://127.0.0.1", training_id="test-increment-v1",
            train_model=train_increment,
        )

    def test_authenticated_clients_follow_two_fenced_rounds_and_preserve_private_inputs(self):
        from hf2l.backends.exchange import ExchangeStore

        self.federation = self.new_space("listener-federation", profile="fedavg.v1")["id"]
        for participant, _ in PARTICIPANTS:
            self.member(participant, ["reader", "contributor"], {"participant": participant},
                        space=self.federation)
        self.register_type("model.global", publish_roles=["publisher"], space=self.federation)
        self.register_type("training.update", visibility="private", publish_roles=["contributor"],
                           space=self.federation)
        owner = ExchangeStore(None, None, client=self.sdk("owner"), wait_seconds=15)
        self.addCleanup(owner.close)
        stores = {}
        for participant, _ in PARTICIPANTS:
            store = ExchangeStore(None, None, client=self.sdk(participant), wait_seconds=15)
            self.addCleanup(store.close)
            stores[participant] = store
        initial = initialize_model(self.directory / "listener-initial", "exchange")
        base = owner.initialize_repository(self.federation, initial, private=True).revision
        route = f"/v2/spaces/{self.federation}"
        self.assertEqual(self.client.get(route + "/refs/main").status_code, 401)

        with ExitStack() as stack:
            listeners = {participant: stack.enter_context(self.listener(store, participant))
                         for participant, store in stores.items()}
            for number in (1, 2):
                inputs = {}
                for participant, listener in listeners.items():
                    self.assertEqual(listener.poll_once(), "submitted")
                    self.assertEqual(listener.poll_once(), "idle")
                    job = listener.state["jobs"][base]
                    self.assertEqual(job["source_round"], number - 1)
                    inputs[participant] = job["result"]["revision"]
                    record = owner.client.get_record(self.federation, inputs[participant])
                    self.assertEqual(record.metadata["base_record_id"], base)
                    self.assertEqual(record.creator_bindings["participant"], participant)
                    peer = "bob" if participant == "alice" else "alice"
                    denied = self.request("GET", route + "/records/" + record.id, peer)
                    self.assertEqual(denied.status_code, 404)
                self.assertEqual(owner.resolve_revision(self.federation, "main"), base)
                result = run_round(owner, RoundConfig(
                    repo_id=self.federation, output_dir=self.directory / f"listener-owner-{number}",
                    selection="claim", publish=True, expected_base_revision=base,
                    claim_lease_seconds=10, require_concurrent_publication=True, array_backend="numpy"))
                assert_round(self, result, base, number)
                record = owner.client.get_record(self.federation, result.publication.revision)
                self.assertEqual(set(record.metadata["inputs"]), set(inputs.values()))
                base = result.publication.revision
                self.assertEqual(owner.resolve_revision(self.federation, "main"), base)

        # Re-opening does not itself start another training job. Each client's
        # saved submission state must survive and retain both completed rounds.
        for participant, store in stores.items():
            with self.listener(store, participant) as listener:
                self.assertEqual(listener.state["completed_round"], 1)
                self.assertEqual(len(listener.state["jobs"]), 2)
                self.assertIsNone(listener.state["active"])
        records = list(owner.client.records(self.federation, kind="training.update", state="published"))
        self.assertEqual(len(records), 4)


if __name__ == "__main__":
    unittest.main()
