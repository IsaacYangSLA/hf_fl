"""Client and owner listeners coordinate real multi-round federated workflows."""

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
from hf2l.listener.client import ClientListener
from hf2l.listener.owner import OwnerListener
from hf2l.round.config import RoundConfig
from tests.support.v3_helpers import checkpoint_value, initialize_model, write_checkpoint


ROOT = Path(__file__).resolve().parents[1]
PARTICIPANTS = {"alice": 1, "bob": 3}


def train_increment(base_dir, output_dir, options):
    """Produce transparent example-weighted results with real safetensors."""
    starting = checkpoint_value(base_dir)
    examples = PARTICIPANTS[options["participant"]]
    write_checkpoint(output_dir, starting + examples)
    return {"num_examples": examples, "starting_value": starting}


def assert_publication(test, job, base, number):
    test.assertEqual(job["status"], "published")
    test.assertEqual(job["source_round"], number - 1)
    result = job["result"]
    test.assertEqual(result["status"], "published")
    test.assertEqual(result["base"]["revision"], base)
    test.assertEqual(result["round_number"], number)
    test.assertEqual(checkpoint_value(Path(result["aggregate_dir"])), 2.5 * number)
    test.assertEqual(
        {entry["participant"]: entry["coefficient"] for entry in result["eligible"]},
        {"alice": 0.25, "bob": 0.75},
    )
    return result["publication"]["revision"]


@unittest.skipUnless(os.name == "posix", "Listener state uses POSIX filesystem locks")
class LocalOwnerListenerIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hf2l-owner-listener-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.root = self.directory / "store"
        self.repo = "automated-model"
        self.store = LocalStore(self.root, "owner")
        self.addCleanup(self.store.close)
        initial = initialize_model(self.directory / "initial", "local")
        self.base = self.store.initialize_repository(self.repo, initial, private=True).revision
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

    def arguments(self, name, *, once=False):
        arguments = [
            sys.executable, "-m", "hf2l.cli", "listen", "--backend", "local",
            "--endpoint", str(self.root), "--local-principal", name,
            "--repo-id", self.repo, "--state-dir", str(self.directory / name),
            "--poll-interval", "0.05", "--max-backoff", "0.1",
        ]
        if name == "owner":
            arguments += ["--role", "owner", "--minimum-participants", "2"]
        else:
            arguments += ["--participant", name, "--plugin", str(self.plugin)]
        arguments += ["--once"] if once else ["--max-rounds", "2"]
        return arguments

    def start_listener(self, name):
        log_path = self.directory / (name + ".log")
        output = log_path.open("w", encoding="utf-8")
        self.addCleanup(output.close)
        process = subprocess.Popen(
            self.arguments(name), cwd=ROOT, stdout=output, stderr=subprocess.STDOUT,
        )
        self.addCleanup(self.stop_process, process)
        self.processes[name] = process
        self.logs[name] = log_path

    def wait_for_event(self, name, event):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            output = self.logs[name].read_text(encoding="utf-8")
            self.assertIsNone(self.processes[name].poll(), output)
            # A process can still be writing its final line when we read it.
            lines = output.splitlines(keepends=True)
            for line in lines:
                if not line.endswith("\n"):
                    continue
                try:
                    message = json.loads(line)
                except ValueError:
                    continue
                if message.get("event") == event:
                    return
            time.sleep(0.02)
        self.fail(f"{name} did not emit {event}:\n{output}")

    def read_state(self, name):
        return json.loads((self.directory / name / "state.json").read_text(encoding="utf-8"))

    def test_three_cli_processes_complete_two_rounds_without_manual_aggregation(self):
        # With just Alice's submission, the owner must keep watching the same
        # base until Bob arrives, despite main itself remaining unchanged.
        self.start_listener("alice")
        self.wait_for_event("alice", "submitted")
        self.start_listener("owner")
        self.wait_for_event("owner", "not_ready")
        self.assertEqual(self.store.resolve_revision(self.repo, "main"), self.base)
        self.assertEqual(self.read_state("owner")["completed_round"], -1)
        self.start_listener("bob")

        for name, process in self.processes.items():
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.fail("Listener processes did not finish:\n" + "\n".join(
                    path.read_text(encoding="utf-8") for path in self.logs.values()))
            self.assertEqual(process.returncode, 0, self.logs[name].read_text(encoding="utf-8"))

        state = self.read_state("owner")
        self.assertEqual(state["completed_round"], 1)
        self.assertIsNone(state["active"])
        self.assertEqual(len(state["jobs"]), 2)
        next_base = assert_publication(self, state["jobs"][self.base], self.base, 1)
        final_base = assert_publication(self, state["jobs"][next_base], next_base, 2)
        self.assertEqual(self.store.resolve_revision(self.repo, "main"), final_base)
        for participant in PARTICIPANTS:
            state = self.read_state(participant)
            self.assertEqual(state["completed_round"], 1)
            self.assertIsNone(state["active"])
            self.assertEqual(set(state["jobs"]), {self.base, next_base})
            self.assertEqual({job["status"] for job in state["jobs"].values()}, {"submitted"})
        candidates, _ = self.store.discover_submissions(self.repo)
        self.assertEqual(len(candidates), 4)

        # A fresh owner invocation resumes its durable state and waits for new
        # inputs; it must not aggregate the previous round a second time.
        result = subprocess.run(self.arguments("owner", once=True), cwd=ROOT,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.store.resolve_revision(self.repo, "main"), final_base)
        state = self.read_state("owner")
        self.assertEqual(state["completed_round"], 1)
        self.assertEqual(sum(job["status"] == "published" for job in state["jobs"].values()), 2)


# Import only the shared fixture, so unittest does not collect another module's
# integration test classes as additional tests here.
_exchange_available = all(importlib.util.find_spec(name) is not None for name in (
    "boto3", "moto", "sqlalchemy", "jwt", "fastapi", "hf2l_exchange"))
if not _exchange_available and os.environ.get("EXCHANGE_REQUIRE_TESTS") == "1":
    raise ImportError("Owner listener integration requires the exchange service/test dependencies")
if _exchange_available:
    _spec = importlib.util.spec_from_file_location(
        "owner_listener_exchange_support", ROOT / "packages/exchange/tests/support.py")
    _support = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_support)
    _ExchangeTestCase = _support.ExchangeTestCase
else:
    _ExchangeTestCase = unittest.TestCase


@unittest.skipUnless(_exchange_available and os.name == "posix",
                     "Exchange integration dependencies and POSIX locks are required")
class ExchangeOwnerListenerIntegrationTests(_ExchangeTestCase):
    def sdk(self, subject):
        from hf2l_exchange.client import ExchangeClient
        from hf2l_exchange.worker import tick

        client = ExchangeClient(
            "http://127.0.0.1", self.auth(subject)["Authorization"].split(" ", 1)[1],
            http=self.client, allow_local_http=True, sleep=lambda _: tick(self.transfers))
        self.addCleanup(client.close)
        return client

    def client_listener(self, store, participant):
        return ClientListener(
            store, repo_id=self.federation, participant=participant,
            state_dir=self.directory / ("client-" + participant),
            source_id="http://127.0.0.1", training_id="owner-integration-increment-v1",
            train_model=train_increment,
        )

    def owner_listener(self, store):
        return OwnerListener(
            store, config=RoundConfig(
                repo_id=self.federation, output_dir=self.directory / "owner-output",
                publish=True, minimum_participants=2, array_backend="numpy",
                claim_lease_seconds=10, require_concurrent_publication=True),
            state_dir=self.directory / "owner-listener", source_id="http://127.0.0.1",
        )

    def test_owner_and_authenticated_clients_coordinate_two_fenced_rounds(self):
        from hf2l.backends.exchange import ExchangeStore

        self.federation = self.new_space("automated-federation", profile="fedavg.v1")["id"]
        for participant in PARTICIPANTS:
            self.member(participant, ["reader", "contributor"], {"participant": participant},
                        space=self.federation)
        self.register_type("model.global", publish_roles=["publisher"], space=self.federation)
        self.register_type("training.update", visibility="private", publish_roles=["contributor"],
                           space=self.federation)
        owner = ExchangeStore(None, None, client=self.sdk("owner"), wait_seconds=15)
        self.addCleanup(owner.close)
        stores = {}
        for participant in PARTICIPANTS:
            store = ExchangeStore(None, None, client=self.sdk(participant), wait_seconds=15)
            self.addCleanup(store.close)
            stores[participant] = store
        initial = initialize_model(self.directory / "initial", "exchange")
        base = owner.initialize_repository(self.federation, initial, private=True).revision
        route = f"/v2/spaces/{self.federation}"
        self.assertEqual(self.client.get(route + "/refs/main").status_code, 401)

        with ExitStack() as stack:
            listeners = {name: stack.enter_context(self.client_listener(store, name))
                         for name, store in stores.items()}
            coordinator = stack.enter_context(self.owner_listener(owner))
            for number in (1, 2):
                self.assertEqual(coordinator.poll_once(), "not_ready")
                self.assertEqual(listeners["alice"].poll_once(), "submitted")
                self.assertEqual(coordinator.poll_once(), "not_ready")
                self.assertEqual(owner.resolve_revision(self.federation, "main"), base)
                self.assertEqual(listeners["bob"].poll_once(), "submitted")
                inputs = {}
                for participant, listener in listeners.items():
                    self.assertEqual(listener.poll_once(), "idle")
                    job = listener.state["jobs"][base]
                    self.assertEqual(job["source_round"], number - 1)
                    inputs[participant] = job["result"]["revision"]
                    record = owner.client.get_record(self.federation, inputs[participant])
                    self.assertEqual(record.metadata["base_record_id"], base)
                    self.assertEqual(record.creator_bindings["participant"], participant)
                    peer = "bob" if participant == "alice" else "alice"
                    self.assertEqual(self.request("GET", route + "/records/" + record.id, peer).status_code,
                                     404)

                self.assertEqual(coordinator.poll_once(), "published")
                job = coordinator.state["jobs"][base]
                next_base = assert_publication(self, job, base, number)
                self.assertTrue(job["result"]["claim_id"])
                published = owner.client.get_record(self.federation, next_base)
                self.assertEqual(set(published.metadata["inputs"]), set(inputs.values()))
                self.assertEqual(owner.resolve_revision(self.federation, "main"), next_base)
                base = next_base
            self.assertEqual(coordinator.state["completed_round"], 1)
            self.assertEqual(len(coordinator.state["jobs"]), 2)

        with self.owner_listener(owner) as coordinator:
            self.assertEqual(coordinator.poll_once(), "not_ready")
            self.assertEqual(coordinator.state["completed_round"], 1)
            self.assertEqual(sum(job["status"] == "published"
                                 for job in coordinator.state["jobs"].values()), 2)
        self.assertEqual(owner.resolve_revision(self.federation, "main"), base)
        for participant, store in stores.items():
            with self.client_listener(store, participant) as listener:
                self.assertEqual(listener.state["completed_round"], 1)
                self.assertEqual(len(listener.state["jobs"]), 2)
                self.assertIsNone(listener.state["active"])
        records = list(owner.client.records(self.federation, kind="training.update", state="published"))
        self.assertEqual(len(records), 4)


if __name__ == "__main__":
    unittest.main()
