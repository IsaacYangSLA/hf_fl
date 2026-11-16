# Exchange environment variables

Exported by `hf2l-exchange export-contract` from the Go executable's embedded reference.
When configuration changes, update `internal/config/config.go` and
`internal/app/contractdata/exchange-environment.md` in `packages/exchange`,
rebuild the executable, then export the contracts again.

Defaults describe the Go configuration defaults and environment loaders; the
export command copies this maintained reference rather than deriving it from source.
Required combinations and bounds are enforced by the Go settings validators. SDK/application
configuration is separate; this table covers the Exchange server and worker settings.

| Variable | Default | Settings field | Notes |
|---|---|---|---|
| `EXCHANGE_ADMIN_SUBJECT` | `""` | `AuthSettings.AdminSubject` |  |
| `EXCHANGE_ALLOW_LOCAL_HTTP` | `false` | `AuthSettings.AllowLocalHTTP` |  |
| `EXCHANGE_ALLOW_LOCAL_HTTP` | `false` | `Settings.AllowLocalHTTP` |  |
| `EXCHANGE_ALLOW_LOCAL_HTTP` | `false` | `StorageSettings.AllowLocalHTTP` |  |
| `EXCHANGE_AUDIENCE` | `"exchange"` | `AuthSettings.Audience` |  |
| `EXCHANGE_COORDINATION_SECONDS` | `300` | `Settings.CoordinationSeconds` |  |
| `EXCHANGE_DATABASE_URL` | `"sqlite:///exchange-v2.db"` | `DatabaseSettings.URL` |  |
| `EXCHANGE_DOCS_ENABLED` | `false` | `Settings.DocsEnabled` |  |
| `EXCHANGE_DOWNLOAD_BROKER_PRINCIPAL_IDS` | `[]` | `AuthSettings.DownloadBrokerPrincipalIDs` | Comma-separated canonical principal IDs. |
| `EXCHANGE_DRAFT_SECONDS` | `86400` | `Settings.DraftSeconds` |  |
| `EXCHANGE_EVENT_RETENTION_SECONDS` | `2592000` | `WorkerSettings.EventRetentionSeconds` | Overrides `EXCHANGE_WORKER_EVENT_RETENTION_SECONDS` when set. |
| `EXCHANGE_GRANT_SECONDS` | `300` | `StorageSettings.GrantSeconds` |  |
| `EXCHANGE_ISSUER` | `""` | `AuthSettings.Issuer` |  |
| `EXCHANGE_JWKS_CACHE_SECONDS` | `300` | `AuthSettings.JWKSCacheSeconds` |  |
| `EXCHANGE_JWKS_TIMEOUT` | `5` | `AuthSettings.JWKSTimeout` |  |
| `EXCHANGE_JWKS_URL` | `""` | `AuthSettings.JWKSURL` |  |
| `EXCHANGE_JWT_PUBLIC_KEY` | `""` | `AuthSettings.PublicKey` |  |
| `EXCHANGE_MAX_BODY_BYTES` | `1048576` | `Settings.MaxBodyBytes` |  |
| `EXCHANGE_OPERATION_RETENTION_SECONDS` | `864000` | `WorkerSettings.OperationRetentionSeconds` | Overrides `EXCHANGE_WORKER_OPERATION_RETENTION_SECONDS` when set. |
| `EXCHANGE_PART_SIZE` | `8388608` | `StorageSettings.PartSize` |  |
| `EXCHANGE_POOL_OVERFLOW` | `10` | `DatabaseSettings.PoolOverflow` |  |
| `EXCHANGE_POOL_RECYCLE` | `1800` | `DatabaseSettings.PoolRecycle` |  |
| `EXCHANGE_POOL_SIZE` | `5` | `DatabaseSettings.PoolSize` |  |
| `EXCHANGE_POOL_TIMEOUT` | `30` | `DatabaseSettings.PoolTimeout` |  |
| `EXCHANGE_PROVISIONING_PRINCIPAL_IDS` | `[]` | `AuthSettings.ProvisioningPrincipalIDs` | Comma-separated canonical principal IDs. |
| `EXCHANGE_S3_ACCESS_KEY` | `""` | `StorageSettings.AccessKey` |  |
| `EXCHANGE_S3_BUCKET` | `""` | `StorageSettings.Bucket` |  |
| `EXCHANGE_S3_ENDPOINT` | `""` | `StorageSettings.Endpoint` |  |
| `EXCHANGE_S3_PREFIX` | `"exchange-v2/"` | `StorageSettings.Prefix` |  |
| `EXCHANGE_S3_PUBLIC_ENDPOINT` | `""` | `StorageSettings.PublicEndpoint` |  |
| `EXCHANGE_S3_REGION` | `"us-east-1"` | `StorageSettings.Region` |  |
| `EXCHANGE_S3_SECRET_KEY` | `""` | `StorageSettings.SecretKey` |  |
| `EXCHANGE_S3_SESSION_TOKEN` | `""` | `StorageSettings.SessionToken` |  |
| `EXCHANGE_TRUSTED_BACKEND_SECRET` | `""` | `AuthSettings.TrustedBackendSecret` |  |
| `EXCHANGE_WORKER_BATCH_SIZE` | `32` | `WorkerSettings.BatchSize` |  |
| `EXCHANGE_WORKER_CLEANUP_CONCURRENCY` | `2` | `WorkerSettings.CleanupConcurrency` |  |
| `EXCHANGE_WORKER_EVENT_RETENTION_SECONDS` | `2592000` | `WorkerSettings.EventRetentionSeconds` |  |
| `EXCHANGE_WORKER_FAILURE_SECONDS` | `86400` | `WorkerSettings.FailureSeconds` |  |
| `EXCHANGE_WORKER_LEASE_SECONDS` | `300` | `WorkerSettings.LeaseSeconds` |  |
| `EXCHANGE_WORKER_OPERATION_RETENTION_SECONDS` | `864000` | `WorkerSettings.OperationRetentionSeconds` |  |
| `EXCHANGE_WORKER_POLL_SECONDS` | `1` | `WorkerSettings.PollSeconds` |  |
| `EXCHANGE_WORKER_RECOVER_AFTER` | `30` | `WorkerSettings.RecoverAfter` |  |
| `EXCHANGE_WORKER_VERIFY_CONCURRENCY` | `2` | `WorkerSettings.VerifyConcurrency` |  |
| `EXCHANGE_WORKLOAD_AUDIENCE` | `"exchange-workload"` | `AuthSettings.WorkloadAudience` |  |
| `EXCHANGE_WORKLOAD_ISSUER` | `""` | `AuthSettings.WorkloadIssuer` |  |
| `EXCHANGE_WORKLOAD_PUBLIC_KEY` | `""` | `AuthSettings.WorkloadPublicKey` |  |
