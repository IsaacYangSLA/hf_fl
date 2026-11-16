# Historical validation records

These records preserve the original inputs, source revisions, results and
limitations. They include earlier Python service implementations. Their test
counts and successful commands are evidence for those recorded baselines,
not qualification of the current native Go services or current deployment.
No new service execution is claimed by this documentation audit.

| Record | Original scope |
| --- | --- |
| [Exchange remote validation](2026-09-23-exchange-remote.md) | PostgreSQL and object-storage behavior before follow-up fixes |
| [Exchange remediation](2026-09-23-exchange-remediation.md) | Follow-up fixes and storage compatibility |
| [Repository remediation](2026-10-08-repository-remediation.md) | Application and client correctness fixes |
| [Development test plan](2026-10-08-colossus-test-plan.md) and [results](2026-10-08-colossus-results.md) | Recorded compatibility and process checks |
| [Multi-job implementation](2026-10-09-multi-job-implementation.md) | Original managed CPU execution qualification |

Use the [documentation index](../README.md), [Go Exchange guide](../GO_EXCHANGE.md)
and [Go manager guide](../GO_JOB_MANAGER.md) for current instructions. Source
links to removed files point at a fixed historical repository revision; they
are reference material, not files installed by current packages.
