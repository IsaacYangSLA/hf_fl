"""Durable owner automation uses the same immutable rounds as client listeners."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hf2l.backends.local import LocalStore
from hf2l.core.ports import PublicationUncertain
from hf2l.core.protocol import ROUND_FILE
from hf2l.fedavg_runner import run_round
from hf2l.listener.client import ClientListener
from hf2l.listener.engine import ListenerStateError
from hf2l.listener.owner import OwnerListener, UncertainAggregation
from hf2l.round.config import RoundConfig
from tests.support.v3_helpers import checkpoint_value, initialize_model, write_checkpoint


class OwnerListenerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hf2l-owner-listener-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = LocalStore(self.root / "store", "owner")
        self.addCleanup(self.store.close)
        initial = initialize_model(self.root / "initial", "local")
        self.base = self.store.initialize_repository("repo", initial, private=True).revision
        self.state_dir = self.root / "owner-state"
        self.config = RoundConfig(repo_id="repo", output_dir=self.root / "unused-output")

    def listener(self, **overrides):
        options = dict(store=self.store, config=self.config, state_dir=self.state_dir,
                       source_id="local:test-store", configuration_id="numpy-owner-v1")
        options.update(overrides)
        return OwnerListener(**options)

    def state(self):
        return json.loads((self.state_dir / "state.json").read_text())

    def submit(self, participant="alice"):
        count = {"alice": 1, "bob": 3, "carol": 2}[participant]
        client_store = LocalStore(self.store.root, participant)
        self.addCleanup(client_store.close)

        def train(base_dir, output_dir, options):
            write_checkpoint(output_dir, checkpoint_value(base_dir) + count)
            return {"num_examples": count}

        with ClientListener(client_store, repo_id="repo", participant=participant,
                            state_dir=self.root / ("client-" + participant),
                            source_id="local:test-store", training_id="increment-v1",
                            train_model=train) as client:
            self.assertEqual(client.poll_once(), "submitted")

    def submit_pair(self):
        self.submit("alice")
        self.submit("bob")

    def download_main(self, name="main-inspection"):
        revision = self.store.resolve_reference("repo").revision
        output = self.root / name
        self.store.download_snapshot("repo", revision, output)
        return revision, output, json.loads((output / ROUND_FILE).read_text())

    def advance(self, round_number, name):
        folder = initialize_model(self.root / name, "local")
        record = json.loads((folder / ROUND_FILE).read_text())
        record["round"] = round_number
        (folder / ROUND_FILE).write_text(json.dumps(record))
        current = self.store.resolve_reference("repo")
        return self.store.publish_aggregate(
            "repo", folder, ["config.json", "model.safetensors", ROUND_FILE],
            expected_base=current.revision, next_round=round_number, tag=None,
            reference=current).revision

    def test_not_ready_repolls_same_base_using_only_metadata(self):
        with self.listener() as owner:
            with patch.object(self.store, "download_snapshot", wraps=self.store.download_snapshot) as download:
                self.assertEqual(owner.poll_once(), "not_ready")
                self.assertEqual(owner.poll_once(), "not_ready")
            self.assertTrue(download.call_args_list)
            self.assertTrue(all(call.kwargs.get("allow_patterns") for call in download.call_args_list))
            self.submit("alice")
            self.assertEqual(owner.poll_once(), "not_ready")
            self.submit("bob")
            self.assertEqual(owner.poll_once(), "published")
        self.assertEqual(self.state()["completed_round"], 0)

    def test_two_client_rounds_publish_weighted_models_without_manual_owner_rounds(self):
        bases = [self.base]
        with self.listener() as owner:
            for number in (1, 2):
                self.submit_pair()
                self.assertEqual(owner.poll_once(), "published")
                revision, output, record = self.download_main(f"inspect-{number}")
                self.assertEqual(record["base_revision"], bases[-1])
                self.assertEqual(record["round"], number)
                self.assertEqual(checkpoint_value(output), 2.5 * number)
                self.assertEqual({item["participant"]: item["coefficient"] for item in record["submissions"]},
                                 {"alice": 0.25, "bob": 0.75})
                self.assertEqual(owner.state["jobs"][bases[-1]]["status"], "published")
                bases.append(revision)
                self.assertEqual(owner.poll_once(), "not_ready")
        self.assertEqual(self.state()["completed_round"], 1)
        with self.listener() as restarted:
            self.assertEqual(restarted.poll_once(), "not_ready")
        self.assertEqual(self.store.resolve_reference("repo").revision, bases[-1])

    def test_minimum_participants_is_applied_before_publication(self):
        self.submit_pair()
        with self.listener(config=replace(self.config, minimum_participants=3)) as owner:
            self.assertEqual(owner.poll_once(), "not_ready")
            self.assertEqual(self.store.resolve_reference("repo").revision, self.base)
            self.submit("carol")
            self.assertEqual(owner.poll_once(), "published")
        _, output, record = self.download_main()
        self.assertEqual(len(record["submissions"]), 3)
        self.assertAlmostEqual(checkpoint_value(output), 14 / 6, places=6)

    def test_allowlist_filters_readiness_and_actual_aggregation(self):
        self.submit_pair()
        allowlist = self.root / "allowlist.json"
        allowlist.write_text(json.dumps({"alice": "alice", "carol": "carol"}))
        with self.listener(config=replace(self.config, allowlist=allowlist)) as owner:
            self.assertEqual(owner.poll_once(), "not_ready")
            self.submit("carol")
            self.assertEqual(owner.poll_once(), "published")
        _, _, record = self.download_main()
        self.assertEqual({item["participant"] for item in record["submissions"]}, {"alice", "carol"})

    def test_metadata_commit_for_completed_source_round_is_not_aggregated_again(self):
        self.submit_pair()
        with self.listener() as owner:
            self.assertEqual(owner.poll_once(), "published")
            metadata_revision = self.advance(0, "metadata-only")
            with patch.object(self.store, "publish_aggregate", wraps=self.store.publish_aggregate) as publish:
                self.assertEqual(owner.poll_once(), "skipped")
                self.assertEqual(owner.poll_once(), "idle")
            publish.assert_not_called()
        self.assertEqual(self.state()["jobs"][metadata_revision]["status"], "skipped")

    def test_failed_prepublication_attempt_can_restart_without_reusing_output_directory(self):
        self.submit_pair()
        attempts = []

        def fail_first_actual(store, config, **kwargs):
            if config.publish:
                attempts.append(config)
                if len(attempts) == 1:
                    config.output_dir.mkdir(parents=True)
                    (config.output_dir / "partial").write_text("interrupted reduction")
                    raise ConnectionError("safe prepublication failure")
            return run_round(store, config, **kwargs)

        with patch("hf2l.listener.owner.run_round", side_effect=fail_first_actual):
            with self.listener() as owner:
                with self.assertRaises(ConnectionError):
                    owner.poll_once()
            self.assertEqual(self.store.resolve_reference("repo").revision, self.base)
            with self.listener() as restarted:
                self.assertEqual(restarted.poll_once(), "published")
        self.assertEqual(len(attempts), 2)
        self.assertNotEqual(attempts[0].output_dir, attempts[1].output_dir)
        self.assertFalse(attempts[0].output_dir.exists())
        self.assertEqual(attempts[0].run_state, attempts[1].run_state)
        self.assertEqual(attempts[1].expected_base_revision, self.base)

    def test_main_advance_after_failed_initial_probe_keeps_restart_state_readable(self):
        with self.listener() as owner:
            with patch.object(owner, "_probe", side_effect=ConnectionError("metadata unavailable")):
                with self.assertRaises(ConnectionError):
                    owner.poll_once()
            self.assertIsNone(owner.state["jobs"][self.base]["source_round"])
            next_revision = self.advance(1, "advanced-after-probe-failure")
            self.assertEqual(owner.poll_once(), "not_ready")
            self.assertEqual(owner.state["jobs"][self.base]["status"], "skipped")
        with self.listener() as restarted:
            self.assertEqual(restarted.poll_once(), "not_ready")
            self.assertEqual(restarted.state["active"], next_revision)

    def test_publish_then_connection_loss_stops_until_operator_reconciles(self):
        self.submit_pair()
        original = self.store.publish_aggregate

        def publish_then_fail(*args, **kwargs):
            original(*args, **kwargs)
            raise ConnectionError("response was lost after publication")

        with self.listener() as owner:
            with patch.object(self.store, "publish_aggregate", side_effect=publish_then_fail) as publish:
                with self.assertRaises(UncertainAggregation):
                    owner.poll_once()
                with self.assertRaises(UncertainAggregation):
                    owner.poll_once()
                self.assertEqual(publish.call_count, 1)
        self.assertNotEqual(self.store.resolve_reference("repo").revision, self.base)
        self.assertEqual(self.state()["jobs"][self.base]["status"], "uncertain")
        with self.listener() as restarted:
            with self.assertRaises(UncertainAggregation):
                restarted.poll_once()
            restarted.resolve_uncertain("published")
            self.assertEqual(restarted.poll_once(), "not_ready")
        self.assertEqual(self.state()["completed_round"], 0)
        self.assertEqual(self.state()["jobs"][self.base]["status"], "published")

    def test_failure_at_remote_boundary_can_be_retried_only_after_explicit_reconciliation(self):
        self.submit_pair()
        with self.listener() as owner:
            with patch.object(self.store, "publish_aggregate", side_effect=ConnectionError("not sent")):
                with self.assertRaises(UncertainAggregation):
                    owner.poll_once()
            self.assertEqual(self.store.resolve_reference("repo").revision, self.base)
            owner.resolve_uncertain("retry")
            self.assertEqual(owner.poll_once(), "published")
        self.assertEqual(self.state()["completed_round"], 0)

    def test_interrupt_during_publication_is_uncertain_after_restart(self):
        self.submit_pair()
        with self.listener() as owner:
            with patch.object(self.store, "publish_aggregate", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    owner.poll_once()
        self.assertEqual(self.state()["jobs"][self.base]["status"], "publishing")
        with self.listener() as restarted:
            self.assertEqual(restarted.state["jobs"][self.base]["status"], "uncertain")
            with self.assertRaises(UncertainAggregation):
                restarted.poll_once()
        self.assertEqual(self.store.resolve_reference("repo").revision, self.base)

    def test_unknown_claim_outcome_before_publication_hook_also_stops_retries(self):
        self.submit_pair()

        def uncertain_acquisition(store, config, **kwargs):
            if config.publish:
                raise PublicationUncertain("completed claim cannot be replayed")
            return run_round(store, config, **kwargs)

        with patch("hf2l.listener.owner.run_round", side_effect=uncertain_acquisition):
            with self.listener() as owner:
                with self.assertRaises(UncertainAggregation):
                    owner.poll_once()
        self.assertEqual(self.state()["jobs"][self.base]["status"], "uncertain")
        with self.listener() as restarted:
            with self.assertRaises(UncertainAggregation):
                restarted.poll_once()

    def test_coordination_capability_selects_claims_and_preserves_recovery_state(self):
        self.submit_pair()
        capabilities = replace(self.store.capabilities, fenced_coordination=True,
                               requires_coordination_for_publication=True)
        actual_configs = []
        saved_claim = {"claim_id": "server-claim", "acquisition_key": "durable-key"}

        def unresolved_claim(store, config, **kwargs):
            if not config.publish:
                self.assertEqual(config.selection, "discover")
                return run_round(store, config, **kwargs)
            self.assertEqual(config.selection, "claim")
            actual_configs.append(config)
            if len(actual_configs) == 1:
                config.run_state.write_text(json.dumps(saved_claim))
            else:
                self.assertEqual(json.loads(config.run_state.read_text()), saved_claim)
            raise PublicationUncertain("claim completion must be reconciled")

        with patch.object(self.store, "capabilities", capabilities):
            with patch("hf2l.listener.owner.run_round", side_effect=unresolved_claim):
                with self.listener() as owner:
                    with self.assertRaises(UncertainAggregation):
                        owner.poll_once()
                with self.listener() as restarted:
                    restarted.resolve_uncertain("retry")
                    with self.assertRaises(UncertainAggregation):
                        restarted.poll_once()
        self.assertEqual(len(actual_configs), 2)
        self.assertEqual(actual_configs[0].run_state, actual_configs[1].run_state)
        self.assertNotEqual(actual_configs[0].output_dir, actual_configs[1].output_dir)
        self.assertNotIn(actual_configs[0].output_dir, actual_configs[0].run_state.parents)

    def test_final_state_write_failure_does_not_allow_automatic_duplicate_publication(self):
        self.submit_pair()
        with self.listener() as owner:
            original = owner._save

            def fail_after_publication():
                if self.store.resolve_reference("repo").revision != self.base:
                    raise OSError("disk is full")
                original()

            with patch.object(owner, "_save", side_effect=fail_after_publication):
                with self.assertRaises((OSError, UncertainAggregation)):
                    owner.poll_once()
        with self.listener() as restarted:
            with self.assertRaises(UncertainAggregation):
                restarted.poll_once()
        _, _, record = self.download_main()
        self.assertEqual(record["round"], 1)

    def test_main_change_between_readiness_and_aggregation_never_publishes_stale_model(self):
        self.submit_pair()
        changed = []

        def advance_before_actual(store, config, **kwargs):
            if config.publish:
                changed.append(self.advance(1, "concurrent-owner"))
            return run_round(store, config, **kwargs)

        with patch("hf2l.listener.owner.run_round", side_effect=advance_before_actual):
            with self.listener() as owner:
                with self.assertRaisesRegex(ValueError, "Main changed"):
                    owner.poll_once()
        self.assertEqual(len(changed), 1)
        self.assertEqual(self.store.resolve_reference("repo").revision, changed[0])
        self.assertNotEqual(self.state()["jobs"][self.base]["status"], "published")
        with self.listener() as restarted:
            self.assertEqual(restarted.poll_once(), "not_ready")

    def test_same_pinned_revision_cannot_change_its_source_round_between_probes(self):
        original = self.store.download_snapshot

        def change_round_metadata(repo_id, revision, destination, **kwargs):
            original(repo_id, revision, destination, **kwargs)
            if revision == self.base and kwargs.get("allow_patterns") == ROUND_FILE:
                path = destination / ROUND_FILE
                record = json.loads(path.read_text())
                record["round"] = 1
                path.write_text(json.dumps(record))

        with self.listener() as owner:
            self.assertEqual(owner.poll_once(), "not_ready")
            with patch.object(self.store, "download_snapshot", side_effect=change_round_metadata):
                with self.assertRaisesRegex(ValueError, "Pinned round metadata changed"):
                    owner.poll_once()
            self.assertEqual(owner.state["jobs"][self.base]["source_round"], 0)
        self.assertEqual(self.store.resolve_reference("repo").revision, self.base)

    def test_owner_configuration_and_source_are_bound_to_existing_state(self):
        with self.listener():
            pass
        for changes in ({"source_id": "another-store"},
                        {"configuration_id": "another-plugin"},
                        {"config": replace(self.config, minimum_participants=3)},
                        {"config": replace(self.config, weighting="uniform")}):
            with self.subTest(changes=changes):
                with self.assertRaises(ListenerStateError):
                    with self.listener(**changes):
                        pass

    def test_allowlist_content_is_bound_even_when_path_stays_the_same(self):
        allowlist = self.root / "allowlist.json"
        allowlist.write_text(json.dumps({"alice": "alice", "bob": "bob"}))
        config = replace(self.config, allowlist=allowlist)
        with self.listener(config=config):
            pass
        allowlist.write_text(json.dumps({"alice": "alice", "carol": "carol"}))
        with self.assertRaises(ListenerStateError):
            with self.listener(config=config):
                pass

    def test_live_allowlist_mutation_requires_reconciliation_before_next_poll(self):
        self.submit_pair()
        allowlist = self.root / "allowlist.json"
        allowlist.write_text(json.dumps({"alice": "alice", "bob": "bob"}))
        with self.listener(config=replace(self.config, allowlist=allowlist)) as owner:
            allowlist.write_text(json.dumps({"alice": "alice", "carol": "carol"}))
            with self.assertRaises(ListenerStateError):
                owner.poll_once()
        self.assertEqual(self.store.resolve_reference("repo").revision, self.base)

    def test_allowlist_mutated_during_aggregation_blocks_the_publication_boundary(self):
        self.submit_pair()
        allowlist = self.root / "allowlist.json"
        allowlist.write_text(json.dumps({"alice": "alice", "bob": "bob"}))

        def mutate_policy_before_hook(store, config, **kwargs):
            if config.publish:
                callback = kwargs["before_publish"]

                def changed_policy(context, aggregate_dir):
                    allowlist.write_text(json.dumps({"alice": "alice", "carol": "carol"}))
                    callback(context, aggregate_dir)

                kwargs["before_publish"] = changed_policy
            return run_round(store, config, **kwargs)

        with self.listener(config=replace(self.config, allowlist=allowlist)) as owner:
            with patch("hf2l.listener.owner.run_round", side_effect=mutate_policy_before_hook):
                with patch.object(self.store, "publish_aggregate", wraps=self.store.publish_aggregate) as publish:
                    with self.assertRaises(ListenerStateError):
                        owner.poll_once()
                    publish.assert_not_called()
        self.assertEqual(self.store.resolve_reference("repo").revision, self.base)

    def test_same_state_directory_cannot_have_two_owner_processes(self):
        with self.listener():
            with self.assertRaises(ListenerStateError):
                with self.listener():
                    pass

    def test_bounded_run_counts_publications(self):
        self.submit_pair()
        with self.listener() as owner:
            self.assertEqual(owner.run(poll_interval=0.001, max_backoff=0.001, max_rounds=1), 1)
        self.assertEqual(self.state()["completed_round"], 0)

    def test_no_credentials_or_plugin_arguments_are_stored_in_state_identity(self):
        marker = "private-model-secret"
        config = replace(self.config, plugin="tests.test_owner_listener", plugin_arg=("secret=" + marker,))
        with self.listener(config=config, source_id="https://server.test/?access=" + marker):
            pass
        self.assertNotIn(marker, (self.state_dir / "state.json").read_text())


if __name__ == "__main__":
    unittest.main()
