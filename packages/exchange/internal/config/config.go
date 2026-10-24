// Package config supplies component-specific Exchange configuration.
// Configuration errors name only trusted fields; secret values never enter errors.
package config

import (
	"errors"
	"math"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type DatabaseSettings struct {
	URL          string  `json:"url"`
	PoolSize     int     `json:"pool_size"`
	PoolOverflow int     `json:"pool_overflow"`
	PoolTimeout  float64 `json:"pool_timeout"`
	PoolRecycle  int64   `json:"pool_recycle"`
}
type AuthSettings struct {
	Issuer                     string   `json:"issuer"`
	Audience                   string   `json:"audience"`
	PublicKey                  string   `json:"public_key"`
	JWKSURL                    string   `json:"jwks_url"`
	AdminSubject               string   `json:"admin_subject"`
	JWKSTimeout                float64  `json:"jwks_timeout"`
	JWKSCacheSeconds           int64    `json:"jwks_cache_seconds"`
	AllowLocalHTTP             bool     `json:"allow_local_http"`
	WorkloadIssuer             string   `json:"workload_issuer"`
	WorkloadAudience           string   `json:"workload_audience"`
	WorkloadPublicKey          string   `json:"workload_public_key"`
	TrustedBackendSecret       string   `json:"trusted_backend_secret"`
	ProvisioningPrincipalIDs   []string `json:"provisioning_principal_ids"`
	DownloadBrokerPrincipalIDs []string `json:"download_broker_principal_ids"`
}
type StorageSettings struct {
	Endpoint       string `json:"endpoint"`
	PublicEndpoint string `json:"public_endpoint"`
	Bucket         string `json:"bucket"`
	Region         string `json:"region"`
	AccessKey      string `json:"access_key"`
	SecretKey      string `json:"secret_key"`
	Prefix         string `json:"prefix"`
	GrantSeconds   int64  `json:"grant_seconds"`
	PartSize       int64  `json:"part_size"`
	AllowLocalHTTP bool   `json:"allow_local_http"`
	SessionToken   string `json:"session_token"`
}
type WorkerSettings struct {
	LeaseSeconds              int64   `json:"lease_seconds"`
	FailureSeconds            int64   `json:"failure_seconds"`
	PollSeconds               float64 `json:"poll_seconds"`
	VerifyConcurrency         int     `json:"verify_concurrency"`
	CleanupConcurrency        int     `json:"cleanup_concurrency"`
	BatchSize                 int     `json:"batch_size"`
	RecoverAfter              int64   `json:"recover_after"`
	OperationRetentionSeconds int64   `json:"operation_retention_seconds"`
	EventRetentionSeconds     int64   `json:"event_retention_seconds"`
}
type Settings struct {
	Database            DatabaseSettings `json:"database"`
	Auth                AuthSettings     `json:"auth"`
	Storage             StorageSettings  `json:"storage"`
	Worker              WorkerSettings   `json:"worker"`
	AllowLocalHTTP      bool             `json:"allow_local_http"`
	DocsEnabled         bool             `json:"docs_enabled"`
	MaxBodyBytes        int64            `json:"max_body_bytes"`
	DraftSeconds        int64            `json:"draft_seconds"`
	CoordinationSeconds int64            `json:"coordination_seconds"`
}

// Error deliberately contains no supplied configuration value.
type Error struct{ Field string }

func (e *Error) Error() string   { return "invalid Exchange configuration: " + e.Field }
func invalid(field string) error { return &Error{Field: field} }
func DefaultDatabase() DatabaseSettings {
	return DatabaseSettings{URL: "sqlite:///exchange-v2.db", PoolSize: 5, PoolOverflow: 10, PoolTimeout: 30, PoolRecycle: 1800}
}
func DefaultAuth() AuthSettings {
	return AuthSettings{Audience: "exchange", JWKSTimeout: 5, JWKSCacheSeconds: 300, WorkloadAudience: "exchange-workload", ProvisioningPrincipalIDs: []string{}, DownloadBrokerPrincipalIDs: []string{}}
}
func DefaultStorage() StorageSettings {
	return StorageSettings{Region: "us-east-1", Prefix: "exchange-v2/", GrantSeconds: 300, PartSize: 8388608}
}
func DefaultWorker() WorkerSettings {
	return WorkerSettings{LeaseSeconds: 300, FailureSeconds: 86400, PollSeconds: 1, VerifyConcurrency: 2, CleanupConcurrency: 2, BatchSize: 32, RecoverAfter: 30, OperationRetentionSeconds: 864000, EventRetentionSeconds: 2592000}
}
func DefaultSettings() Settings {
	return Settings{Database: DefaultDatabase(), Auth: DefaultAuth(), Storage: DefaultStorage(), Worker: DefaultWorker(), MaxBodyBytes: 1048576, DraftSeconds: 86400, CoordinationSeconds: 300}
}

// RequireTLS permits cleartext only for explicitly enabled local development.
func RequireTLS(raw string, allowLocalHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return invalid("URL")
	}
	if u.Scheme == "https" {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	local := host == "localhost" || host == "testserver"
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		local = true
	}
	if u.Scheme == "http" && allowLocalHTTP && local {
		return nil
	}
	return invalid("HTTPS")
}
func validDuration(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 1 && v < float64(math.MaxInt64)/float64(time.Second)
}
func (s DatabaseSettings) Validate() error {
	if !strings.HasPrefix(s.URL, "sqlite:") && !strings.HasPrefix(s.URL, "postgresql:") && !strings.HasPrefix(s.URL, "postgresql+psycopg:") {
		return invalid("database.url")
	}
	if s.PoolSize < 1 || s.PoolOverflow < 0 || s.PoolSize > int(^uint(0)>>1)-s.PoolOverflow {
		return invalid("database.pool")
	}
	if !validDuration(s.PoolTimeout) {
		return invalid("database.pool_timeout")
	}
	if s.PoolRecycle < 1 || s.PoolRecycle > int64(math.MaxInt64)/int64(time.Second) {
		return invalid("database.pool_recycle")
	}
	return nil
}
func (s AuthSettings) WorkloadsEnabled() bool { return s.WorkloadIssuer != "" }
func (s AuthSettings) Validate() error {
	if (s.WorkloadIssuer != "") != (s.WorkloadPublicKey != "") {
		return invalid("auth.workload_identity")
	}
	if s.WorkloadsEnabled() {
		if RequireTLS(s.WorkloadIssuer, s.AllowLocalHTTP) != nil {
			return invalid("auth.workload_issuer")
		}
		if s.WorkloadIssuer == s.Issuer || s.WorkloadAudience == "" {
			return invalid("auth.workload_identity")
		}
		if len([]byte(s.TrustedBackendSecret)) < 32 || len(s.ProvisioningPrincipalIDs) == 0 {
			return invalid("auth.backend_ingress")
		}
	} else if s.TrustedBackendSecret != "" || len(s.ProvisioningPrincipalIDs) > 0 || len(s.DownloadBrokerPrincipalIDs) > 0 {
		return invalid("auth.managed_principals")
	}
	for _, ids := range [][]string{s.ProvisioningPrincipalIDs, s.DownloadBrokerPrincipalIDs} {
		for _, id := range ids {
			if len(id) != 64 || strings.Trim(id, "0123456789abcdef") != "" {
				return invalid("auth.managed_principal_id")
			}
		}
	}
	if s.Issuer == "" || s.Audience == "" || (s.PublicKey != "") == (s.JWKSURL != "") {
		return invalid("auth.identity")
	}
	if RequireTLS(s.Issuer, s.AllowLocalHTTP) != nil {
		return invalid("auth.issuer")
	}
	if s.JWKSURL != "" && RequireTLS(s.JWKSURL, s.AllowLocalHTTP) != nil {
		return invalid("auth.jwks_url")
	}
	if !validDuration(s.JWKSTimeout) {
		return invalid("auth.jwks_timeout")
	}
	if s.JWKSCacheSeconds < 1 || s.JWKSCacheSeconds > int64(math.MaxInt64)/int64(time.Second) {
		return invalid("auth.jwks_cache_seconds")
	}
	return nil
}
func (s StorageSettings) Validate() error {
	if s.Bucket == "" {
		return invalid("storage.bucket")
	}
	for _, ep := range []string{s.Endpoint, s.PublicEndpoint} {
		if ep != "" && RequireTLS(ep, s.AllowLocalHTTP) != nil {
			return invalid("storage.endpoint")
		}
	}
	if (s.AccessKey != "") != (s.SecretKey != "") {
		return invalid("storage.credentials")
	}
	if s.SessionToken != "" && s.AccessKey == "" {
		return invalid("storage.session_token")
	}
	if len([]byte(s.Prefix)) > 800 || strings.HasPrefix(s.Prefix, "/") {
		return invalid("storage.prefix")
	}
	for _, part := range strings.Split(s.Prefix, "/") {
		if part == ".." {
			return invalid("storage.prefix")
		}
	}
	if s.GrantSeconds < 1 || s.GrantSeconds > 3600 {
		return invalid("storage.grant_seconds")
	}
	if s.PartSize < 5242880 || s.PartSize > 5368709120 {
		return invalid("storage.part_size")
	}
	return nil
}
func (s WorkerSettings) Validate() error {
	if s.LeaseSeconds < 1 || s.FailureSeconds < 1 || s.VerifyConcurrency < 1 || s.CleanupConcurrency < 1 || s.BatchSize < 1 || s.RecoverAfter < 1 || s.OperationRetentionSeconds < 1 || s.EventRetentionSeconds < 1 {
		return invalid("worker.positive_settings")
	}
	if !validDuration(s.PollSeconds) {
		return invalid("worker.poll_seconds")
	}
	if s.FailureSeconds < s.LeaseSeconds {
		return invalid("worker.failure_seconds")
	}
	return nil
}
func (s Settings) Validate(component string) error {
	if component != "server" && component != "worker" && component != "database" {
		return invalid("component")
	}
	if err := s.Database.Validate(); err != nil {
		return err
	}
	if component == "server" {
		if err := s.Auth.Validate(); err != nil {
			return err
		}
	}
	if component == "server" || component == "worker" {
		if err := s.Storage.Validate(); err != nil {
			return err
		}
		if err := s.Worker.Validate(); err != nil {
			return err
		}
		// Draft and grant bounds below keep this sum comfortably within int64.
		if s.DraftSeconds < 1 || s.DraftSeconds > 604800 {
			return invalid("draft_seconds")
		}
		if s.Worker.OperationRetentionSeconds <= s.DraftSeconds+s.Storage.GrantSeconds+86400 {
			return invalid("operation_retention_seconds")
		}
	}
	if s.MaxBodyBytes < 1 {
		return invalid("max_body_bytes")
	}
	if s.DraftSeconds < 1 || s.DraftSeconds > 604800 {
		return invalid("draft_seconds")
	}
	if s.CoordinationSeconds < 1 || s.CoordinationSeconds > 3600 {
		return invalid("coordination_seconds")
	}
	return nil
}
func env(name, fallback string) string {
	if v, ok := os.LookupEnv("EXCHANGE_" + name); ok {
		return v
	}
	return fallback
}
func integer(name string, v int64) (int64, error) {
	n, e := strconv.ParseInt(strings.TrimSpace(env(name, strconv.FormatInt(v, 10))), 10, 64)
	if e != nil {
		return 0, invalid(name)
	}
	return n, nil
}
func count(name string, v int) (int, error) {
	n, e := integer(name, int64(v))
	if e != nil {
		return 0, e
	}
	if int64(int(n)) != n {
		return 0, invalid(name)
	}
	return int(n), nil
}
func real(name string, v float64) (float64, error) {
	n, e := strconv.ParseFloat(strings.TrimSpace(env(name, strconv.FormatFloat(v, 'g', -1, 64))), 64)
	if e != nil || math.IsNaN(n) || math.IsInf(n, 0) {
		return 0, invalid(name)
	}
	return n, nil
}
func boolean(name string, v bool) (bool, error) {
	d := "false"
	if v {
		d = "true"
	}
	switch strings.ToLower(env(name, d)) {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	}
	return false, invalid(name)
}
func list(name string) []string {
	out := []string{}
	for _, v := range strings.Split(env(name, ""), ",") {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
func DatabaseFromEnv() (DatabaseSettings, error) {
	s := DefaultDatabase()
	var e error
	s.URL = env("DATABASE_URL", s.URL)
	if s.PoolSize, e = count("POOL_SIZE", s.PoolSize); e != nil {
		return s, e
	}
	if s.PoolOverflow, e = count("POOL_OVERFLOW", s.PoolOverflow); e != nil {
		return s, e
	}
	if s.PoolTimeout, e = real("POOL_TIMEOUT", s.PoolTimeout); e != nil {
		return s, e
	}
	if s.PoolRecycle, e = integer("POOL_RECYCLE", s.PoolRecycle); e != nil {
		return s, e
	}
	return s, s.Validate()
}
func AuthFromEnv() (AuthSettings, error) {
	s := DefaultAuth()
	var e error
	s.Issuer = env("ISSUER", "")
	s.Audience = env("AUDIENCE", s.Audience)
	s.PublicKey = env("JWT_PUBLIC_KEY", "")
	s.JWKSURL = env("JWKS_URL", "")
	s.AdminSubject = env("ADMIN_SUBJECT", "")
	if s.JWKSTimeout, e = real("JWKS_TIMEOUT", s.JWKSTimeout); e != nil {
		return s, e
	}
	if s.JWKSCacheSeconds, e = integer("JWKS_CACHE_SECONDS", s.JWKSCacheSeconds); e != nil {
		return s, e
	}
	if s.AllowLocalHTTP, e = boolean("ALLOW_LOCAL_HTTP", false); e != nil {
		return s, e
	}
	s.WorkloadIssuer = env("WORKLOAD_ISSUER", "")
	s.WorkloadAudience = env("WORKLOAD_AUDIENCE", s.WorkloadAudience)
	s.WorkloadPublicKey = env("WORKLOAD_PUBLIC_KEY", "")
	s.TrustedBackendSecret = env("TRUSTED_BACKEND_SECRET", "")
	s.ProvisioningPrincipalIDs = list("PROVISIONING_PRINCIPAL_IDS")
	s.DownloadBrokerPrincipalIDs = list("DOWNLOAD_BROKER_PRINCIPAL_IDS")
	return s, s.Validate()
}
func StorageFromEnv() (StorageSettings, error) {
	s := DefaultStorage()
	var e error
	s.Endpoint = env("S3_ENDPOINT", "")
	s.PublicEndpoint = env("S3_PUBLIC_ENDPOINT", "")
	s.Bucket = env("S3_BUCKET", "")
	s.Region = env("S3_REGION", s.Region)
	s.AccessKey = env("S3_ACCESS_KEY", "")
	s.SecretKey = env("S3_SECRET_KEY", "")
	s.SessionToken = env("S3_SESSION_TOKEN", "")
	s.Prefix = env("S3_PREFIX", s.Prefix)
	if s.GrantSeconds, e = integer("GRANT_SECONDS", s.GrantSeconds); e != nil {
		return s, e
	}
	if s.PartSize, e = integer("PART_SIZE", s.PartSize); e != nil {
		return s, e
	}
	if s.AllowLocalHTTP, e = boolean("ALLOW_LOCAL_HTTP", false); e != nil {
		return s, e
	}
	return s, s.Validate()
}
func WorkerFromEnv() (WorkerSettings, error) {
	s := DefaultWorker()
	var e error
	for _, v := range []struct {
		name string
		ptr  *int64
	}{{"LEASE_SECONDS", &s.LeaseSeconds}, {"FAILURE_SECONDS", &s.FailureSeconds}, {"RECOVER_AFTER", &s.RecoverAfter}, {"OPERATION_RETENTION_SECONDS", &s.OperationRetentionSeconds}, {"EVENT_RETENTION_SECONDS", &s.EventRetentionSeconds}} {
		if *v.ptr, e = integer("WORKER_"+v.name, *v.ptr); e != nil {
			return s, e
		}
	}
	for _, v := range []struct {
		name string
		ptr  *int
	}{{"VERIFY_CONCURRENCY", &s.VerifyConcurrency}, {"CLEANUP_CONCURRENCY", &s.CleanupConcurrency}, {"BATCH_SIZE", &s.BatchSize}} {
		if *v.ptr, e = count("WORKER_"+v.name, *v.ptr); e != nil {
			return s, e
		}
	}
	if s.PollSeconds, e = real("WORKER_POLL_SECONDS", s.PollSeconds); e != nil {
		return s, e
	}
	if _, ok := os.LookupEnv("EXCHANGE_OPERATION_RETENTION_SECONDS"); ok {
		if s.OperationRetentionSeconds, e = integer("OPERATION_RETENTION_SECONDS", s.OperationRetentionSeconds); e != nil {
			return s, e
		}
	}
	if _, ok := os.LookupEnv("EXCHANGE_EVENT_RETENTION_SECONDS"); ok {
		if s.EventRetentionSeconds, e = integer("EVENT_RETENTION_SECONDS", s.EventRetentionSeconds); e != nil {
			return s, e
		}
	}
	return s, s.Validate()
}
func FromEnv(component string) (Settings, error) {
	s := DefaultSettings()
	var e error
	if s.Database, e = DatabaseFromEnv(); e != nil {
		return s, e
	}
	if component == "server" {
		if s.Auth, e = AuthFromEnv(); e != nil {
			return s, e
		}
	}
	if component != "database" {
		if s.Storage, e = StorageFromEnv(); e != nil {
			return s, e
		}
	}
	if s.Worker, e = WorkerFromEnv(); e != nil {
		return s, e
	}
	if s.AllowLocalHTTP, e = boolean("ALLOW_LOCAL_HTTP", false); e != nil {
		return s, e
	}
	if s.DocsEnabled, e = boolean("DOCS_ENABLED", false); e != nil {
		return s, e
	}
	if s.MaxBodyBytes, e = integer("MAX_BODY_BYTES", s.MaxBodyBytes); e != nil {
		return s, e
	}
	if s.DraftSeconds, e = integer("DRAFT_SECONDS", s.DraftSeconds); e != nil {
		return s, e
	}
	if s.CoordinationSeconds, e = integer("COORDINATION_SECONDS", s.CoordinationSeconds); e != nil {
		return s, e
	}
	return s, s.Validate(component)
}

// Duration converts validated positive seconds without overflowing time.Duration.
func Duration(seconds float64) (time.Duration, error) {
	if !validDuration(seconds) {
		return 0, invalid("duration")
	}
	return time.Duration(seconds * float64(time.Second)), nil
}

// IsError permits safe CLI classification without formatting private values.
func IsError(err error) bool { var e *Error; return errors.As(err, &e) }
func (s Settings) String() string {
	return "ExchangeSettings{redacted}"
}

func (s Settings) GoString() string         { return s.String() }
func (s AuthSettings) String() string       { return "ExchangeAuthSettings{redacted}" }
func (s AuthSettings) GoString() string     { return s.String() }
func (s StorageSettings) String() string    { return "ExchangeStorageSettings{redacted}" }
func (s StorageSettings) GoString() string  { return s.String() }
func (s DatabaseSettings) String() string   { return "ExchangeDatabaseSettings{redacted}" }
func (s DatabaseSettings) GoString() string { return s.String() }
