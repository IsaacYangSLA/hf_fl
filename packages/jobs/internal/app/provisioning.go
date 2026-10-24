package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/artifacts"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/certificates"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/controller"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/exchange"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/provision"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/secrets"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/transfer"
)

type remoteBindings interface {
	IsRemote(context.Context, executor.ExecutionIdentity) (bool, error)
	Binding(context.Context, executor.ExecutionIdentity, string, string) (map[string]any, error)
	ProxyAlive(context.Context, executor.ExecutionIdentity) (bool, error)
}
type executionLogs interface {
	ReadLogs(context.Context, executor.ExecutionIdentity, int64, int64) (map[string]any, error)
}
type executionArtifacts interface {
	ReadArtifact(context.Context, executor.ExecutionIdentity, string, int64) ([]byte, error)
}
type executionState interface {
	ReadState(context.Context, executor.ExecutionIdentity, string, int64) ([]byte, error)
}
type reconciliationRoot interface {
	ReconciliationRoot(context.Context, executor.ExecutionIdentity) (string, error)
}

func isRemote(ctx context.Context, s *Services, id executor.ExecutionIdentity) (bool, error) {
	if n, ok := s.Node.(remoteBindings); ok {
		return n.IsRemote(ctx, id)
	}
	return false, nil
}
func transferID(id executor.ExecutionIdentity) transfer.ExecutionIdentity {
	return transfer.ExecutionIdentity{JobID: id.JobID, AttemptID: id.AttemptID, ComponentID: id.ComponentID, Epoch: id.Epoch}
}
func expiryTime(v any) (time.Time, bool) {
	if t, ok := store.Time(v); ok {
		return t, true
	}
	var f float64
	switch n := v.(type) {
	case json.Number:
		var e error
		f, e = n.Float64()
		if e != nil {
			return time.Time{}, false
		}
	case float64:
		f = n
	case int64:
		f = float64(n)
	case int:
		f = float64(n)
	default:
		return time.Time{}, false
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f <= 0 || f > float64(math.MaxInt64)/1e9 {
		return time.Time{}, false
	}
	return time.Unix(0, int64(f*1e9)).UTC(), true
}

type grantSnapshot struct {
	job, resource map[string]any
	participant   *string
}

func managerGrantSnapshot(ctx context.Context, tx *store.Tx, b transfer.ExecutionBinding, grantID, resourceID, specHash string, lock bool) (grantSnapshot, error) {
	var snapshot grantSnapshot
	deny := func() (grantSnapshot, error) { return snapshot, domain.Err(401, "execution_grant_revoked") }
	suffix := ""
	if lock {
		suffix = tx.ForUpdate()
	}
	job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id = ?"+suffix, b.JobID)
	if e != nil {
		return snapshot, e
	}
	attempt, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE id = ?", b.AttemptID)
	if e != nil {
		return snapshot, e
	}
	if job == nil || attempt == nil || attempt["job_id"] != b.JobID || intValue(attempt["epoch"]) != b.Epoch || intValue(job["epoch"]) != b.Epoch || intValue(attempt["number"]) != intValue(job["current_attempt"]) {
		return deny()
	}
	state := strValue(job["state"])
	if state != "PROVISIONING" && state != "STARTING" && state != "RUNNING" {
		return deny()
	}
	if deadline, ok := store.Time(job["deadline_at"]); !ok || !deadline.After(time.Now()) {
		return deny()
	}
	rows, e := tx.All(ctx, "SELECT * FROM jm_provisioning_resources WHERE job_id = ? AND attempt_id = ? AND component_id = ? AND kind = ? AND deleted_at IS NULL"+suffix, b.JobID, b.AttemptID, b.ComponentID, "workload_grant")
	if e != nil {
		return snapshot, e
	}
	if len(rows) != 1 || rows[0]["state"] == "deleted" {
		return snapshot, domain.Err(503, "execution_grant_unavailable")
	}
	resource := rows[0]
	details := objMap(resource["details_json"])
	if strValue(details["space_id"]) != b.SpaceID || strValue(resource["external_id"]) == "" {
		return deny()
	}
	if grantID != "" && resource["external_id"] != grantID {
		return deny()
	}
	if resourceID != "" && resource["id"] != resourceID {
		return deny()
	}
	if specHash != "" && job["spec_hash"] != specHash {
		return deny()
	}
	spec, e := provision.JobSpec(job)
	if e != nil {
		return snapshot, e
	}
	found := false
	for _, c := range spec.Components {
		if c.ComponentID == b.ComponentID {
			snapshot.participant = c.ParticipantID
			found = true
			break
		}
	}
	if !found {
		return deny()
	}
	snapshot.job, snapshot.resource = job, resource
	return snapshot, nil
}
func currentGrant(ctx context.Context, s *Services, client *exchange.Client, b transfer.ExecutionBinding) (map[string]any, *string, error) {
	var snapshot grantSnapshot
	e := s.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		var e error
		snapshot, e = managerGrantSnapshot(ctx, tx, b, "", "", "", false)
		return e
	})
	if e != nil {
		return nil, nil, e
	}
	grantID := strValue(snapshot.resource["external_id"])
	current, e := client.GetGrant(ctx, b.SpaceID, grantID)
	if e != nil {
		return nil, nil, e
	}
	deny := func() (map[string]any, *string, error) { return nil, nil, domain.Err(401, "execution_grant_revoked") }
	if current == nil || current["revoked_at"] != nil && current["revoked_at"] != "" {
		return deny()
	}
	if enabled, exists := current["enabled"]; exists && enabled != true {
		return deny()
	}
	for k, expected := range map[string]string{"job_id": b.JobID, "attempt_id": b.AttemptID, "component_id": b.ComponentID, "space_id": b.SpaceID, "certificate_thumbprint": b.CertificateThumbprint} {
		if strValue(current[k]) != expected {
			return deny()
		}
	}
	if intValue(current["epoch"]) != b.Epoch {
		return deny()
	}
	expiry, ok := expiryTime(current["expires_at"])
	if !ok || !expiry.After(time.Now()) {
		return deny()
	}
	// The network lookup can race cancellation, a successor attempt, or cleanup.
	// Recheck the same durable binding after the Exchange observation.
	var fresh grantSnapshot
	e = s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		var e error
		fresh, e = managerGrantSnapshot(ctx, tx, b, grantID, strValue(snapshot.resource["id"]), strValue(snapshot.job["spec_hash"]), true)
		return e
	})
	if e != nil {
		return nil, nil, e
	}
	current["id"] = grantID
	return current, fresh.participant, nil
}
func issueCurrentWorkload(ctx context.Context, s *Services, b transfer.ExecutionBinding, grant map[string]any, participant *string, gateway bool) (string, error) {
	if s.Broker == nil {
		return "", config.Invalid()
	}
	var token string
	// Keep the current job/resource row locked through signing. Cancellation
	// either commits first and is rejected here, or follows this issuance.
	e := s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		fresh, e := managerGrantSnapshot(ctx, tx, b, strValue(grant["id"]), "", "", true)
		if e != nil {
			return e
		}
		if (fresh.participant == nil) != (participant == nil) || fresh.participant != nil && *fresh.participant != *participant {
			return domain.Err(401, "execution_grant_revoked")
		}
		expiry, ok := expiryTime(grant["expires_at"])
		if !ok {
			return domain.Err(401, "execution_grant_revoked")
		}
		remaining := int64(time.Until(expiry).Seconds())
		if remaining > 300 {
			remaining = 300
		}
		if remaining < 1 {
			return domain.Err(401, "execution_grant_revoked")
		}
		audience := "exchange"
		if gateway {
			audience = "gateway"
		}
		token, e = s.Broker.IssueWorkload(exchange.WorkloadRequest{JobID: b.JobID, AttemptID: b.AttemptID, ComponentID: b.ComponentID, SpaceID: b.SpaceID, GrantID: strValue(grant["id"]), CertificateThumbprint: b.CertificateThumbprint, Epoch: b.Epoch, TTLSeconds: remaining, ParticipantID: fresh.participant, Audience: audience})
		return e
	})
	if e != nil {
		return "", e
	}
	return token, nil
}

func ComposeProvisioner(ctx context.Context, s *Services) (err error) {
	stage := "configuration"
	defer func() {
		if err != nil {
			err = fmt.Errorf("provisioner %s: %w", stage, err)
		}
	}()
	if s.Broker == nil || s.Settings.Workload == nil || s.Settings.Workload.PrivateKey == "" {
		return config.Invalid()
	}
	values, e := s.Settings.Section("provisioner", true)
	if e != nil {
		return e
	}
	required := []string{"root", "exchange_endpoint", "admin_token_file", "client_ca_certificate", "client_ca_key", "managed_exchange_endpoint", "gateway_endpoint", "service_ca_file", "exchange_storage_pool_id", "exchange_storage"}
	if e = config.Keys(values, required, []string{"exchange_ca_file", "allowed_source_hosts", "allow_local_exchange_http", "build_approvals", "socket_root", "storage_pool_id"}); e != nil {
		return e
	}
	root, e := cfgText(values, "root")
	if e != nil {
		return e
	}
	tokenFile, e := cfgText(values, "admin_token_file")
	if e != nil {
		return e
	}
	if _, e = config.ReadSecret(tokenFile); e != nil {
		return e
	}
	caKey, e := cfgText(values, "client_ca_key")
	if e != nil {
		return e
	}
	if _, e = config.ReadSecret(caKey); e != nil {
		return e
	}
	allow, e := config.GetBool(values, "allow_local_exchange_http", false)
	if e != nil {
		return e
	}
	endpoint, e := cfgText(values, "exchange_endpoint")
	if e != nil {
		return e
	}
	exchangeCA, e := config.GetString(values, "exchange_ca_file", "")
	if e != nil {
		return e
	}
	stage = "exchange client"
	client, e := exchange.New(exchange.Config{Endpoint: endpoint, TokenFile: tokenFile, CAFile: exchangeCA, Timeout: 60 * time.Second, Retries: 3, AllowLocalHTTP: allow})
	if e != nil {
		return e
	}
	s.CloseCallbacks = append(s.CloseCallbacks, func() error { client.Close(); return nil })
	w := s.Settings.Workload
	supervisorConfig := transfer.SupervisorConfig{Root: root, SocketRoot: strValue(values["socket_root"]), ClientCACertificate: strValue(values["client_ca_certificate"]), ClientCAKey: caKey, ServiceCAFile: strValue(values["service_ca_file"]), ExchangeEndpoint: strValue(values["managed_exchange_endpoint"]), GatewayEndpoint: strValue(values["gateway_endpoint"]), WorkloadIssuer: w.Issuer, WorkloadPublicKey: w.PublicKey, ExchangeAudience: w.ExchangeAudience, GatewayAudience: w.GatewayAudience}
	supervisorConfig.TokenProvider = func(ctx context.Context, b transfer.ExecutionBinding, gateway bool) (string, error) {
		grant, participant, e := currentGrant(ctx, s, client, b)
		if e != nil {
			return "", e
		}
		return issueCurrentWorkload(ctx, s, b, grant, participant, gateway)
	}
	stage = "execution proxy supervisor"
	supervisor, e := transfer.NewSupervisor(supervisorConfig)
	if e != nil {
		return e
	}
	s.Supervisor = supervisor
	s.CloseCallbacks = append(s.CloseCallbacks, supervisor.Close)
	socketRoot := supervisorConfig.SocketRoot
	if socketRoot == "" {
		socketRoot = root
	}
	stage = "proxy socket root"
	if s.LocalNode != nil {
		linux, ok := s.LocalNode.Backend.(*executor.LinuxExecutor)
		if !ok || filepath.Clean(socketRoot) != filepath.Clean(linux.OwnedRoot) {
			return config.Invalid()
		}
	}
	storagePool, e := config.GetString(values, "storage_pool_id", "")
	if e != nil {
		return e
	}
	if storagePool == "" && s.LocalNode != nil {
		storagePool = s.LocalNode.PoolID
	}
	if storagePool == "" {
		return config.Invalid()
	}
	stage = "manager storage pool"
	if e = validateManagerStoragePool(ctx, s, storagePool, root); e != nil {
		return e
	}
	stage = "object storage pool"
	objectPool, e := validateObjectStorePool(ctx, s)
	if e != nil {
		return e
	}
	stage = "secrets"
	var resolver *secrets.Resolver
	secretSettings, e := s.Settings.Section("secrets", false)
	if e != nil {
		return e
	}
	if len(secretSettings) > 0 {
		if e = config.Keys(secretSettings, []string{"private_root", "references"}, nil); e != nil {
			return e
		}
		approvals, e := secretApprovals(secretSettings["references"])
		if e != nil {
			return e
		}
		resolver, e = secrets.NewResolver(s.DB, strValue(secretSettings["private_root"]), approvals)
		if e != nil {
			return e
		}
	}
	stage = "build approvals"
	approvals := map[string]map[string]any{}
	if input, exists := values["build_approvals"]; exists {
		m, ok := input.(map[string]any)
		if !ok {
			return config.Invalid()
		}
		for k, v := range m {
			a, ok := v.(map[string]any)
			if !ok {
				return config.Invalid()
			}
			approvals[k] = a
		}
	}
	stage = "provisioning callbacks"
	cfg := provision.Config{DB: s.DB, Exchange: client, Root: root, WorkloadIssuer: w.Issuer, StoragePoolID: storagePool, ExchangeStoragePoolID: objectPool, SecretResolver: resolver, BuildApprovals: approvals}
	cfg.AuxiliaryStorageTx = func(ctx context.Context, tx *store.Tx, job map[string]any) ([]map[string]any, error) {
		return RemoteAuxiliaryStorageTx(ctx, s, tx, job)
	}
	cfg.AuxiliaryStorage = func(ctx context.Context, job map[string]any) (rows []map[string]any, err error) {
		err = s.DB.WithTx(ctx, false, func(tx *store.Tx) error { var e error; rows, e = RemoteAuxiliaryStorageTx(ctx, s, tx, job); return e })
		return
	}
	cfg.RemoteAuxiliaryCleanup = func(ctx context.Context, job map[string]any, rows []map[string]any) (map[string][]map[string]any, error) {
		return RemoteAuxiliaryCleanup(ctx, s, job, rows)
	}
	cfg.ProxyEndpoint = func(id executor.ExecutionIdentity) string {
		remote, e := isRemote(context.Background(), s, id)
		if e != nil {
			return ""
		}
		if remote {
			return "remote:" + id.Key()
		}
		p, e := supervisor.Endpoint(transferID(id))
		if e != nil {
			return ""
		}
		return p
	}
	cfg.ExecutionBindings = func(ctx context.Context, job, attempt map[string]any, c domain.ComponentSpec, space, principal string) (map[string]any, error) {
		id := executor.ExecutionIdentity{JobID: strValue(job["id"]), AttemptID: strValue(attempt["id"]), ComponentID: c.ComponentID, Epoch: intValue(attempt["epoch"])}
		remote, e := isRemote(ctx, s, id)
		if e != nil {
			return nil, e
		}
		if remote {
			n, ok := s.Node.(remoteBindings)
			if !ok {
				return nil, config.Invalid()
			}
			return n.Binding(ctx, id, space, principal)
		}
		expected, e := exchange.StableWorkloadPrincipal(w.Issuer, id.JobID, id.ComponentID, c.ParticipantID)
		if e != nil || expected != principal {
			return nil, config.Invalid()
		}
		deadline, ok := store.Time(job["deadline_at"])
		if !ok {
			return nil, config.Invalid()
		}
		binding, e := supervisor.Ensure(ctx, transferID(id), space, deadline)
		if e != nil {
			return nil, e
		}
		result := map[string]any{"proxy_endpoint": binding.ProxyEndpoint, "certificate_thumbprint": binding.CertificateThumbprint}
		if c.ParticipantID != nil {
			spec, e := provision.JobSpec(job)
			if e != nil {
				return nil, e
			}
			found := false
			for _, p := range spec.Participants {
				if p.ParticipantID == *c.ParticipantID {
					data, e := DatasetConfig(s.Settings, p.DatasetBinding, spec.ProjectID, p.ParticipantID)
					if e != nil {
						return nil, e
					}
					runtime := map[string]any{"kind": data["kind"]}
					if data["kind"] == "npz" {
						runtime["path"] = "/job/data/data.npz"
					}
					result["dataset_bindings"] = map[string]any{p.DatasetBinding: runtime}
					found = true
				}
			}
			if !found {
				return nil, config.Invalid()
			}
		}
		return result, nil
	}
	if reader, ok := s.Node.(executionArtifacts); ok {
		cfg.ArtifactReader = reader.ReadArtifact
	}
	cfg.ProxyStopper = func(ctx context.Context, id executor.ExecutionIdentity, confirmed bool) (bool, error) {
		remote, e := isRemote(ctx, s, id)
		if e != nil {
			return false, e
		}
		if remote {
			if !confirmed {
				return false, nil
			}
			peer, ok := s.Node.(remoteBindings)
			if !ok {
				return false, config.Invalid()
			}
			alive, e := peer.ProxyAlive(ctx, id)
			if e != nil {
				return false, e
			}
			return !alive, nil
		}
		return supervisor.Stop(ctx, transferID(id), confirmed)
	}
	cfg.ProxyRestorer = func(ctx context.Context, job, attempt map[string]any) (bool, error) {
		if s.Provisioner == nil {
			return false, config.Invalid()
		}
		space, e := s.Provisioner.OwnedSpace(ctx, strValue(job["id"]))
		if e != nil || space == "" {
			return space == "", e
		}
		spec, e := provision.JobSpec(job)
		if e != nil {
			return false, e
		}
		for _, component := range spec.Components {
			if component.Role == "build" {
				continue
			}
			id := executor.ExecutionIdentity{JobID: strValue(job["id"]), AttemptID: strValue(attempt["id"]), ComponentID: component.ComponentID, Epoch: intValue(attempt["epoch"])}
			remote, e := isRemote(ctx, s, id)
			if e != nil {
				return false, e
			}
			if !remote && s.Node != nil {
				observed, e := s.Node.Inspect(ctx, id)
				if e != nil {
					return false, e
				}
				if strings.EqualFold(observed.State, "RUNNING") {
					alive := ProxyAlive(ctx, id, supervisor)
					if !alive {
						return false, domain.Err(409, "proxy_restart_required")
					}
				}
			}
			if _, e = cfg.ExecutionBindings(ctx, job, attempt, component, space, s.Provisioner.Principal(id.JobID, id.ComponentID, component.ParticipantID)); e != nil {
				return false, e
			}
		}
		return true, nil
	}
	stage = "provisioner constructor"
	provisioner, e := provision.New(cfg)
	if e != nil {
		return e
	}
	s.Provisioner = provisioner
	zero := int64(0)
	stage = "artifact certificate issuer"
	issuer, e := certificates.NewIssuer(certificates.Config{CACertificateFile: strValue(values["client_ca_certificate"]), CAPrivateKeyFile: caKey, GraceSeconds: &zero, MaxLifetimeSeconds: 300})
	if e != nil {
		return e
	}
	stage = "artifact managed gateway"
	managed, e := artifacts.NewManagedGatewayBackend(s.DB, artifacts.ManagedGatewayConfig{Endpoint: strValue(values["gateway_endpoint"]), CAFile: strValue(values["service_ca_file"]), Exchange: client, Workloads: s.Broker, Certificates: issuer})
	if e != nil {
		return e
	}
	stage = "artifact broker"
	broker, e := artifacts.NewBroker(s.Manager, s.DB, artifacts.BrokerConfig{Root: root, ExecutorRoot: executorRoot(s.Settings), Gateway: managed, RemoteRoute: brokerRemoteRoute(s), RemoteRead: brokerRemoteRead(s)})
	if e != nil {
		return e
	}
	s.ArtifactBroker = broker
	s.Provisioner.ArtifactFenceRevoker = broker.Revoke
	if s.Node != nil {
		observer := &controller.AuthoritativePublicationObserver{DB: s.DB, Exchange: client, StateReader: controller.PublicationStateReaderFunc(composeStateReader(s)), Principal: func(job, component, participant string) string {
			var p *string
			if participant != "" {
				p = &participant
			}
			return s.Provisioner.Principal(job, component, p)
		}}
		s.PublicationObserver = observer
		s.Provisioner.PublicationObserver = observer.Observe
	}
	return nil
}
func executorRoot(s config.Settings) string {
	v, _ := s.Section("executor", false)
	return strValue(v["root"])
}
func secretApprovals(value any) (map[string]secrets.Approval, error) {
	entries, ok := value.(map[string]any)
	if !ok {
		return nil, config.Invalid()
	}
	out := map[string]secrets.Approval{}
	for id, raw := range entries {
		row, ok := raw.(map[string]any)
		if !ok {
			return nil, config.Invalid()
		}
		if e := config.Keys(row, []string{"project_id", "path"}, []string{"purpose", "roles", "option_names", "component_ids"}); e != nil {
			return nil, e
		}
		role := []string{}
		options := []string{}
		components := []string{}
		var e error
		if v, ok := row["roles"]; ok {
			role, e = stringsValue(v)
			if e != nil {
				return nil, e
			}
		}
		if v, ok := row["option_names"]; ok {
			options, e = stringsValue(v)
			if e != nil {
				return nil, e
			}
		}
		if v, ok := row["component_ids"]; ok {
			components, e = stringsValue(v)
			if e != nil {
				return nil, e
			}
		}
		out[id] = secrets.Approval{ID: id, ProjectID: strValue(row["project_id"]), Path: strValue(row["path"]), Purpose: strValue(row["purpose"]), Roles: role, OptionNames: options, ComponentIDs: components}
	}
	return out, nil
}
func ProxyAlive(ctx context.Context, id executor.ExecutionIdentity, supervisor *transfer.Supervisor) bool {
	alive, e := supervisor.Alive(ctx, transferID(id))
	return e == nil && alive
}
func composeStateReader(s *Services) func(context.Context, executor.ExecutionIdentity, string, int64) ([]byte, error) {
	return func(ctx context.Context, id executor.ExecutionIdentity, path string, maximum int64) ([]byte, error) {
		if reader, ok := s.Node.(executionState); ok {
			return reader.ReadState(ctx, id, path, maximum)
		}
		rooter, ok := s.Node.(reconciliationRoot)
		if !ok {
			return nil, config.Invalid()
		}
		root, e := rooter.ReconciliationRoot(ctx, id)
		if e != nil {
			return nil, e
		}
		c, e := artifacts.NewCollector(root, artifacts.CollectorOptions{MaxFileBytes: maximum, MaxTotalBytes: maximum})
		if e != nil {
			return nil, e
		}
		defer c.Close()
		b, e := c.Read(path, maximum)
		if errors.Is(e, os.ErrNotExist) {
			return nil, nil
		}
		return b, e
	}
}
