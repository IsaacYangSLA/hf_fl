# Documentation

Use the current guides for setup and behavior. Historical design and validation
records describe their dated source revisions; they do not qualify a deployment
you run today.

## Start and train

| Goal | Guide |
| --- | --- |
| Understand the project and replaceable components | [Repository overview](../README.md) |
| Deploy the beginner services and complete two rounds | [Your first federation](../examples/first_federation/README.md) |
| Reuse a local trainer and configure storage | [Training guide](TRAINING_GUIDE.md) |
| Automate participant training and owner aggregation | [Listeners](CLIENT_LISTENER.md) |
| Configure Hugging Face webhook automation | [FedAvg workflow](FEDAVG_WORKFLOW.md) |
| Run the CIFAR-10 demonstration | [Exchange CIFAR-10 example](../examples/exchange_cifar10/README.md) |

## Operate services

| Goal | Guide |
| --- | --- |
| Deploy Exchange and use its API or SDK | [Exchange runbook](EXCHANGE_V3.md) |
| Understand Exchange service responsibilities | [Service overview](EXCHANGE_SERVICE.md) |
| Install the standalone Exchange package | [Exchange package](../packages/exchange/README.md) |
| Qualify the optional patched S3 implementation | [SeaweedFS deployment](../deploy/seaweedfs/README.md) |
| Configure the manager, dashboard, and runtime | [Job manager](JOB_MANAGER.md), [deployment](../deploy/jobs/README.md) |
| Install the standalone manager package | [Jobs package](../packages/jobs/README.md) |
| Export managed job results | [Job exports](JOB_EXPORTS.md) |

## Architecture and contracts

- [Current architecture](ARCHITECTURE_V3.md) and [diagrams](diagrams/README.md).
- [Multi-job design and implementation status](MULTI_JOB_DESIGN.md).
- Generated [FL document schemas](generated/fl-documents.json),
  [Exchange API](generated/exchange-api.json),
  [Exchange error contract](generated/exchange-errors.json), and
  [Exchange environment settings](generated/exchange-environment.md).
- [Developer scenario index and evidence limits](../tests/support/scenarios.md).

## Historical records

The [design archive](history/README.md) contains superseded proposals and reviews.
These validation records retain their original outcomes and limitations:

- [Exchange remediation](validation/2026-09-23-exchange-remediation.md).
- [Remote Exchange qualification](validation/2026-09-23-exchange-remote.md).
- [Runtime test plan](validation/2026-10-08-colossus-test-plan.md) and
  [results](validation/2026-10-08-colossus-results.md).
- [Repository remediation](validation/2026-10-08-repository-remediation.md).
- [Multi-job implementation](validation/2026-10-09-multi-job-implementation.md).
