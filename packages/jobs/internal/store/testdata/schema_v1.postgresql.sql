-- Frozen Python-reference schema before additive upgrades.

CREATE TABLE auth_login_attempts (
	id VARCHAR(64) NOT NULL, 
	cookie_hash VARCHAR(64) NOT NULL, 
	verifier TEXT NOT NULL, 
	nonce VARCHAR(128) NOT NULL, 
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	used_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id)
)

;

CREATE TABLE auth_logout_replays (
	id VARCHAR(64) NOT NULL, 
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
)

;

CREATE TABLE jm_auth_sessions (
	id VARCHAR(64) NOT NULL, 
	principal_id VARCHAR(256) NOT NULL, 
	issuer VARCHAR(1024) NOT NULL, 
	subject VARCHAR(256) NOT NULL, 
	provider_sid VARCHAR(256), 
	csrf_hash VARCHAR(64) NOT NULL, 
	access_token TEXT, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	checked_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	absolute_expires_at TIMESTAMP WITH TIME ZONE, 
	revoked_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id)
)

;

CREATE TABLE jm_idempotency (
	scope VARCHAR(128) NOT NULL, 
	principal_id VARCHAR(256) NOT NULL, 
	key VARCHAR(256) NOT NULL, 
	request_hash VARCHAR(64) NOT NULL, 
	response_json JSONB NOT NULL, 
	status_code INTEGER NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (scope, principal_id, key)
)

;

CREATE TABLE jm_pools (
	id VARCHAR(128) NOT NULL, 
	name VARCHAR(200) NOT NULL, 
	node_id VARCHAR(128) NOT NULL, 
	cpu_millicores BIGINT NOT NULL, 
	memory_bytes BIGINT NOT NULL, 
	disk_bytes BIGINT NOT NULL, 
	gpu_uuids JSONB NOT NULL, 
	gpu_profiles JSONB NOT NULL, 
	sandbox_profiles JSONB NOT NULL, 
	healthy BOOLEAN NOT NULL, 
	quarantined BOOLEAN NOT NULL, 
	version INTEGER NOT NULL, 
	details_json JSONB NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	CHECK (cpu_millicores >= 0 AND memory_bytes >= 0 AND disk_bytes >= 0 AND version >= 1)
)

;

CREATE TABLE jm_projects (
	id VARCHAR(128) NOT NULL, 
	name VARCHAR(200) NOT NULL, 
	retention_days INTEGER NOT NULL, 
	quota_cpu_millicores BIGINT, 
	quota_memory_bytes BIGINT, 
	quota_disk_bytes BIGINT, 
	quota_gpus INTEGER, 
	max_active_jobs INTEGER, 
	quotas_json JSONB NOT NULL, 
	retained_bytes BIGINT NOT NULL, 
	version INTEGER NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	CHECK (retained_bytes >= 0), 
	CHECK (retention_days >= 0)
)

;

CREATE TABLE jm_schema_revisions (
	revision VARCHAR(64) NOT NULL, 
	applied_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (revision)
)

;

CREATE TABLE jm_approved_sources (
	id VARCHAR(128) NOT NULL, 
	project_id VARCHAR(128), 
	name VARCHAR(200) NOT NULL, 
	allowed_hosts JSONB NOT NULL, 
	policy_json JSONB NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	url VARCHAR(2048) NOT NULL, 
	details_json JSONB NOT NULL, 
	allowed_commits JSONB NOT NULL, 
	enabled BOOLEAN NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(project_id) REFERENCES jm_projects (id)
)

;

CREATE TABLE jm_jobs (
	id VARCHAR(32) NOT NULL, 
	project_id VARCHAR(128) NOT NULL, 
	creator_id VARCHAR(256) NOT NULL, 
	name VARCHAR(200) NOT NULL, 
	spec_json JSONB NOT NULL, 
	spec_hash VARCHAR(64) NOT NULL, 
	state VARCHAR(32) NOT NULL, 
	phase VARCHAR(64), 
	queue_reason JSONB, 
	version INTEGER NOT NULL, 
	current_attempt INTEGER NOT NULL, 
	attempt_count INTEGER NOT NULL, 
	epoch INTEGER NOT NULL, 
	backfill_count INTEGER NOT NULL, 
	current_round INTEGER NOT NULL, 
	target_round INTEGER NOT NULL, 
	cleanup_status VARCHAR(32) NOT NULL, 
	error_code VARCHAR(128), 
	outcome_reason VARCHAR(128), 
	deadline_at TIMESTAMP WITH TIME ZONE, 
	next_attempt_at TIMESTAMP WITH TIME ZONE, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	terminated_at TIMESTAMP WITH TIME ZONE, 
	artifacts_expire_at TIMESTAMP WITH TIME ZONE, 
	purged_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	CHECK (state IN ('QUEUED', 'PROVISIONING', 'STARTING', 'RUNNING', 'RECONCILING', 'NEEDS_ATTENTION', 'CANCELLING', 'SUCCEEDED', 'FAILED', 'CANCELLED')), 
	CHECK (version >= 1 AND epoch >= 0 AND target_round >= 1 AND current_round >= 0 AND backfill_count >= 0), 
	FOREIGN KEY(project_id) REFERENCES jm_projects (id)
)

;

CREATE TABLE jm_participant_bindings (
	id VARCHAR(128) NOT NULL, 
	project_id VARCHAR(128) NOT NULL, 
	participant_id VARCHAR(128) NOT NULL, 
	node_id VARCHAR(128), 
	dataset_label VARCHAR(200) NOT NULL, 
	enabled BOOLEAN NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(project_id) REFERENCES jm_projects (id)
)

;

CREATE TABLE jm_project_members (
	project_id VARCHAR(128) NOT NULL, 
	principal_id VARCHAR(256) NOT NULL, 
	role VARCHAR(24) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (project_id, principal_id), 
	CHECK (role IN ('submitter', 'admin')), 
	FOREIGN KEY(project_id) REFERENCES jm_projects (id)
)

;

CREATE TABLE jm_runtime_images (
	id VARCHAR(128) NOT NULL, 
	project_id VARCHAR(128), 
	name VARCHAR(200) NOT NULL, 
	approved BOOLEAN NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	digest VARCHAR(128) NOT NULL, 
	enabled BOOLEAN NOT NULL, 
	details_json JSONB NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(project_id) REFERENCES jm_projects (id)
)

;

CREATE TABLE jm_secret_references (
	reference VARCHAR(1024), 
	id VARCHAR(128) NOT NULL, 
	project_id VARCHAR(128) NOT NULL, 
	enabled BOOLEAN NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(project_id) REFERENCES jm_projects (id)
)

;

CREATE TABLE jm_artifacts (
	id VARCHAR(32) NOT NULL, 
	job_id VARCHAR(32) NOT NULL, 
	attempt_number INTEGER, 
	kind VARCHAR(64) NOT NULL, 
	name VARCHAR(256) NOT NULL, 
	size_bytes BIGINT NOT NULL, 
	sha256 VARCHAR(64) NOT NULL, 
	storage_key VARCHAR(1024) NOT NULL, 
	state VARCHAR(32) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	expires_at TIMESTAMP WITH TIME ZONE, 
	deleted_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	CHECK (size_bytes >= 0), 
	FOREIGN KEY(job_id) REFERENCES jm_jobs (id)
)

;

CREATE TABLE jm_attempts (
	id VARCHAR(32) NOT NULL, 
	job_id VARCHAR(32) NOT NULL, 
	number INTEGER NOT NULL, 
	epoch INTEGER NOT NULL, 
	state VARCHAR(32) NOT NULL, 
	node_id VARCHAR(128), 
	started_at TIMESTAMP WITH TIME ZONE, 
	ended_at TIMESTAMP WITH TIME ZONE, 
	heartbeat_at TIMESTAMP WITH TIME ZONE, 
	revocation_confirmed BOOLEAN NOT NULL, 
	termination_confirmed BOOLEAN NOT NULL, 
	publication_status VARCHAR(32) NOT NULL, 
	error_code VARCHAR(128), 
	details_json JSONB NOT NULL, 
	resources_json JSONB NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	CHECK (number >= 1 AND epoch >= 1), 
	FOREIGN KEY(job_id) REFERENCES jm_jobs (id), 
	UNIQUE (job_id, epoch), 
	UNIQUE (job_id, number)
)

;

CREATE TABLE jm_events (
	id VARCHAR(32) NOT NULL, 
	job_id VARCHAR(32) NOT NULL, 
	sequence BIGINT NOT NULL, 
	kind VARCHAR(64) NOT NULL, 
	actor_id VARCHAR(256), 
	version INTEGER, 
	epoch INTEGER, 
	data_json JSONB NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(job_id) REFERENCES jm_jobs (id), 
	UNIQUE (job_id, sequence)
)

;

CREATE TABLE jm_job_members (
	job_id VARCHAR(32) NOT NULL, 
	principal_id VARCHAR(256) NOT NULL, 
	role VARCHAR(24) NOT NULL, 
	granted_by VARCHAR(256), 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (job_id, principal_id), 
	CHECK (role IN ('reader', 'operator', 'admin')), 
	FOREIGN KEY(job_id) REFERENCES jm_jobs (id)
)

;

CREATE TABLE jm_log_chunks (
	id VARCHAR(32) NOT NULL, 
	job_id VARCHAR(32) NOT NULL, 
	attempt_number INTEGER, 
	component VARCHAR(128) NOT NULL, 
	sequence BIGINT NOT NULL, 
	data TEXT NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	expires_at TIMESTAMP WITH TIME ZONE, 
	deleted_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	CHECK (length(data) <= 65536), 
	FOREIGN KEY(job_id) REFERENCES jm_jobs (id), 
	UNIQUE (job_id, component, sequence)
)

;

CREATE TABLE jm_allocations (
	id VARCHAR(32) NOT NULL, 
	job_id VARCHAR(32) NOT NULL, 
	attempt_id VARCHAR(32) NOT NULL, 
	component_id VARCHAR(128) NOT NULL, 
	pool_id VARCHAR(128) NOT NULL, 
	cpu_millicores BIGINT NOT NULL, 
	memory_bytes BIGINT NOT NULL, 
	disk_bytes BIGINT NOT NULL, 
	gpu_count INTEGER NOT NULL, 
	epoch INTEGER NOT NULL, 
	state VARCHAR(32) NOT NULL, 
	acknowledged BOOLEAN NOT NULL, 
	termination_confirmed BOOLEAN NOT NULL, 
	details_json JSONB NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	released_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	CHECK (cpu_millicores >= 0 AND memory_bytes >= 0 AND disk_bytes >= 0 AND gpu_count >= 0 AND epoch >= 1), 
	FOREIGN KEY(attempt_id) REFERENCES jm_attempts (id), 
	FOREIGN KEY(job_id) REFERENCES jm_jobs (id), 
	FOREIGN KEY(pool_id) REFERENCES jm_pools (id)
)

;

CREATE TABLE jm_outbox (
	id VARCHAR(32) NOT NULL, 
	job_id VARCHAR(32), 
	attempt_id VARCHAR(32), 
	attempt_number INTEGER, 
	topic VARCHAR(64) NOT NULL, 
	payload_json JSONB NOT NULL, 
	idempotency_key VARCHAR(256) NOT NULL, 
	state VARCHAR(32) NOT NULL, 
	lease_owner VARCHAR(128), 
	lease_until TIMESTAMP WITH TIME ZONE, 
	attempts INTEGER NOT NULL, 
	next_attempt_at TIMESTAMP WITH TIME ZONE, 
	last_error VARCHAR(256), 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(attempt_id) REFERENCES jm_attempts (id), 
	FOREIGN KEY(job_id) REFERENCES jm_jobs (id), 
	UNIQUE (idempotency_key)
)

;

CREATE TABLE jm_provisioning_operations (
	id VARCHAR(32) NOT NULL, 
	job_id VARCHAR(32) NOT NULL, 
	attempt_id VARCHAR(32), 
	component_id VARCHAR(128) NOT NULL, 
	operation VARCHAR(64) NOT NULL, 
	idempotency_key VARCHAR(256) NOT NULL, 
	state VARCHAR(32) NOT NULL, 
	desired_json JSONB NOT NULL, 
	observed_json JSONB NOT NULL, 
	last_error VARCHAR(256), 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(attempt_id) REFERENCES jm_attempts (id), 
	FOREIGN KEY(job_id) REFERENCES jm_jobs (id), 
	UNIQUE (idempotency_key)
)

;

CREATE TABLE jm_provisioning_resources (
	id VARCHAR(32) NOT NULL, 
	job_id VARCHAR(32) NOT NULL, 
	attempt_id VARCHAR(32), 
	component_id VARCHAR(128) NOT NULL, 
	kind VARCHAR(64) NOT NULL, 
	external_id VARCHAR(1024), 
	ownership_json JSONB NOT NULL, 
	details_json JSONB NOT NULL, 
	state VARCHAR(32) NOT NULL, 
	retained BOOLEAN NOT NULL, 
	size_bytes BIGINT NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	deleted_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	FOREIGN KEY(attempt_id) REFERENCES jm_attempts (id), 
	FOREIGN KEY(job_id) REFERENCES jm_jobs (id), 
	UNIQUE (kind, external_id)
)

;

CREATE TABLE jm_gpu_allocations (
	id VARCHAR(32) NOT NULL, 
	allocation_id VARCHAR(32) NOT NULL, 
	pool_id VARCHAR(128) NOT NULL, 
	gpu_uuid VARCHAR(128) NOT NULL, 
	released_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	FOREIGN KEY(allocation_id) REFERENCES jm_allocations (id), 
	FOREIGN KEY(pool_id) REFERENCES jm_pools (id)
)

;
CREATE INDEX ix_auth_login_attempts_expires_at ON auth_login_attempts (expires_at);
CREATE INDEX ix_auth_logout_replays_expires_at ON auth_logout_replays (expires_at);
CREATE INDEX ix_jm_sessions_principal ON jm_auth_sessions (principal_id, revoked_at);
CREATE INDEX ix_jm_jobs_project ON jm_jobs (project_id, created_at, id);
CREATE INDEX ix_jm_jobs_queue ON jm_jobs (state, created_at, id);
CREATE INDEX ix_jm_artifacts_job ON jm_artifacts (job_id, created_at, id);
CREATE INDEX ix_jm_events_job ON jm_events (job_id, sequence);
CREATE INDEX ix_jm_members_principal ON jm_job_members (principal_id, job_id);
CREATE INDEX ix_jm_alloc_pool ON jm_allocations (pool_id, state);
CREATE UNIQUE INDEX uq_jm_live_component ON jm_allocations (job_id, component_id) WHERE released_at IS NULL;
CREATE INDEX ix_jm_outbox_dispatch ON jm_outbox (state, next_attempt_at, lease_until, id);
CREATE INDEX ix_jm_resource_job ON jm_provisioning_resources (job_id, state);
CREATE UNIQUE INDEX uq_jm_live_gpu ON jm_gpu_allocations (gpu_uuid) WHERE released_at IS NULL;
INSERT INTO jm_schema_revisions (revision, applied_at) VALUES ('0001_manager', '2026-01-01 00:00:00.000000');
