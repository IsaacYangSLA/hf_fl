# Real CPU executor verification

The ordinary executor tests use controlled system replies and never launch a
runtime. The opt-in Linux integration fixture exercises a real Go node agent,
its SQLite ledger, and the fixed stock Python application inside qualified
networkless gVisor sandboxes.

Prepare a **new private runtime** using the existing runtime setup, image build,
isolation qualification, and backing-I/O qualification documents. Both original
qualification reports must pass. Keep the profile and the reports it references
private (mode 0600); their hashes and every recorded check are verified before
runtime effects. The worker image must be exactly the image qualified by the
isolation report, with the stock build frontend 1.6.1 and NumPy 2.5.4 installed
offline. No dependencies are installed by this test.

From the jobs Go module, set:

```sh
export HF2L_TEST_QUALIFIED_PROFILE=/absolute/private/runtime/executor-profile.json
export HF2L_TEST_WORKER_IMAGE=sha256:YOUR_QUALIFIED_IMAGE_DIGEST
export HF2L_TEST_EXECUTOR_ROOT=/absolute/private/owned-root/new-executor-test
go test -race -tags integration ./internal/executor \
  -run '^TestQualifiedCPULifecycle$' -count=1 -v
```

The test root must not exist and must be below the profile's owned root. The
node agent needs permission to perform the profile's fixed Docker and system
commands. Use a task-owned daemon with no unrelated workloads; the fixture does
not change daemon settings, pull images, or use host Docker. Allow two CPU
workers, 2 GiB of node memory, and 1 GiB of node disk accounting.

Two build components each perform 128 NumPy gradient updates and remain running.
The test confirms concurrent execution, cancels one component, expires the
other's actual lease and invokes the watchdog, collects artifacts, and verifies
retained disk remains charged. A fresh epoch reuses the first component's bound
state and completes an offline wheel. Cleanup verifies container absence,
authoritative mount and loop-device absence, scratch deletion, retained artifact
deletion, and zero final disk accounting.

This is an executor and build-application test. Full federated training, source
approval, Exchange, authentication, and controller API behavior have separate
integration tests.

A report is retained at `$HF2L_TEST_EXECUTOR_ROOT/report.json`, including source
and artifact hashes, qualification hashes, numeric results, and cleanup proof.
Failed attempts remain separate. If the process is interrupted, recover only
that fixture through its durable Go ledger:

```sh
export HF2L_TEST_RECOVER_EXECUTOR_ROOT="$HF2L_TEST_EXECUTOR_ROOT"
go test -race -tags integration ./internal/executor \
  -run '^TestQualifiedCPURecovery$' -count=1 -v
```

Recovery requires the original fixture report and rejects foreign assignments.
It preserves that report and writes `recovery.json`. It leaves the runtime and
qualified image running for further tests; their operator owns final shutdown.
