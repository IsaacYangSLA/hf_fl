# Current executable scenario inventory

This inventory names tests for the Go manager and Exchange services, and the
retained Python client, training, and execution adapters. A test is a repeatable
check; an inventory reference identifies its source file and function. `::`
separates the file path from the function name. Python references end in `.py`;
Go references end in `.go`.

These references establish where behavior is checked. They do not claim every
test has run or passed in a particular deployment. Real database, storage,
browser, and isolated-execution checks require their explicit prerequisites.
The [Go Exchange guide](../../docs/GO_EXCHANGE.md) and
[Go manager guide](../../docs/GO_JOB_MANAGER.md) describe those gates.

The [earlier 250-row inventory](history/scenarios-wp0.md) is historical. It
includes removed Python server tests and former service behavior. It is not a
one-to-one specification for the current service or a runnable regression suite.
No Python manager or Exchange server is retained to execute that inventory.
The numerical checkpoint fixtures under `tests/goldens` remain immutable; their
recorded hashes are checked separately.

`C-001` and subsequent identifiers label current scenarios. They do not reuse the
historical `S-001` identifiers. The architecture check verifies that each current
reference names an existing test function in the selected source tree.

| ID | Component | Checked behavior | Executable evidence |
| --- | --- | --- | --- |
| C-001 | Checkpoint averaging | Supplied coefficients determine numerical aggregation. | `tests/test_poc.py::test_fedavg_uses_supplied_coefficients` |
| C-002 | Checkpoint layout | Sharded checkpoints are discovered and aggregated. | `tests/test_poc.py::test_sharded_checkpoint_index_is_discovered` |
| C-003 | Local workflow | Immutable inputs survive a complete local round. | `tests/test_v3_end_to_end.py::test_local_round_preserves_immutable_inputs_and_advances_main_once` |
| C-004 | Client listener | Submitted work is not repeated after restart. | `tests/test_client_listener.py::test_pinned_round_is_submitted_once_and_survives_restart` |
| C-005 | Owner listener | Unknown publication outcomes require reconciliation. | `tests/test_owner_listener.py::test_publish_then_connection_loss_stops_until_operator_reconciles` |
| C-006 | Python client | Space profiles and quota updates preserve their request contract. | `packages/exchange/tests/test_client.py::test_space_profile_and_quota_update_wire_contract` |
| C-007 | Python client transfers | Confirmed multipart parts are resumed without leaking control credentials. | `packages/exchange/tests/test_client.py::test_multipart_resume_skips_confirmed_parts_and_separates_credentials` |
| C-008 | Managed Python client | A real local socket streams parts without inherited network-proxy settings. | `packages/exchange/tests/test_managed_client.py::test_real_unix_socket_transport_ignores_environment_proxy_and_streams_parts` |
| C-009 | Go authentication | Human and workload identities remain separate. | `packages/exchange/internal/auth/auth_test.go::TestHumanAuthenticationAndIdentitySeparation` |
| C-010 | Go public service | Record lifecycle, permissions, conditional updates, and pagination are enforced. | `packages/exchange/internal/httpapi/http_test.go::TestNativeHTTPRecordLifecycleRBACETagsAndPagination` |
| C-011 | Go encrypted listener | Actual encrypted requests work and errors hide private details. | `packages/exchange/internal/httpapi/http_test.go::TestNativeHTTPActualHTTPSAndErrorRedaction` |
| C-012 | Go coordination | Acquisition ownership, fences, and repeated requests preserve publication authority. | `packages/exchange/internal/service/coordination_test.go::TestCoordinationLifecycleFencesAndReplay` |
| C-013 | Go retained state | Coordination survives process/store restart. | `packages/exchange/internal/service/coordination_test.go::TestCoordinationRetainedStateAcrossRestarts` |
| C-014 | Go verification | Upload completion and byte verification remain distinct. | `packages/exchange/internal/transfers/transfers_test.go::TestCompletionAndVerificationDistinct` |
| C-015 | Go transfer recovery | A stale operation cannot commit or release its successor. | `packages/exchange/internal/transfers/transfers_test.go::TestStaleOwnerCannotCommitOrReleaseSuccessor` |
| C-016 | Go storage accounting | Physical capacity stays charged through verification failure and cleanup retry. | `packages/exchange/internal/transfers/transfers_test.go::TestVerificationFailureHoldsPhysicalQuotaThroughCleanupRetry` |
| C-017 | Go worker scheduling | Independent background work categories retain separate capacity. | `packages/exchange/internal/worker/worker_test.go::TestTickPoolsKeepIndependentCapacityAndCategory` |
| C-018 | Go job queue | Two jobs run concurrently and a queued third advances after release. | `packages/jobs/internal/scheduler/scheduler_test.go::TestTwoConcurrentJobsAndQueuedThirdStartsAfterRelease` |
| C-019 | Go cancellation | Cancellation wins over an in-flight successful operation. | `packages/jobs/internal/controller/controller_test.go::TestControllerCancellationWinsInflightSuccess` |
| C-020 | Go publication recovery | An unknown publication retains reserved capacity. | `packages/jobs/internal/controller/controller_test.go::TestControllerUnknownPublicationRetainsCapacity` |
| C-021 | Python build adapter | Approved source produces an offline wheel and attempts rotate idempotently. | `packages/jobs/tests/test_build.py::test_actual_offline_wheel_and_idempotent_attempt_rotation` |
| C-022 | Python runtime adapter | The fixed runtime entry point dispatches a build without Exchange. | `packages/jobs/tests/test_build.py::test_fixed_runtime_entrypoint_dispatches_build_without_exchange` |
