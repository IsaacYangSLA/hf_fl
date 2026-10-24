package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/artifacts"
	buildworker "github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/build"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/certificates"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/controller"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/exchange"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/httpapi"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/participants"
)

func participantNodeApprovals(settings config.Settings) ([]participants.ApprovedNode, map[string]participants.ClientConfig, error) {
	values, e := settings.Section("participants", true)
	if e != nil {
		return nil, nil, e
	}
	if e = config.Keys(values, []string{"nodes", "client_certificate", "client_key"}, []string{"agent"}); e != nil {
		return nil, nil, e
	}
	raw, ok := values["nodes"].(map[string]any)
	if !ok || len(raw) == 0 {
		return nil, nil, config.Invalid()
	}
	certificate, e := config.GetString(values, "client_certificate", "")
	if e != nil || certificate == "" {
		return nil, nil, config.Invalid()
	}
	key, e := config.GetString(values, "client_key", "")
	if e != nil || key == "" {
		return nil, nil, config.Invalid()
	}
	if _, e = config.ReadSecret(key); e != nil {
		return nil, nil, e
	}
	var approved []participants.ApprovedNode
	clients := map[string]participants.ClientConfig{}
	for id, value := range raw {
		entry, ok := value.(map[string]any)
		if !ok || domain.ValidateIdentifier(id) != nil {
			return nil, nil, config.Invalid()
		}
		if e = config.Keys(entry, []string{"dataset_bindings", "endpoint", "ca_file"}, []string{"certificate_thumbprint", "certificate_file", "resources", "enabled"}); e != nil {
			return nil, nil, e
		}
		thumb, thumbOK := entry["certificate_thumbprint"]
		file, fileOK := entry["certificate_file"]
		if thumbOK == fileOK {
			return nil, nil, config.Invalid()
		}
		fingerprint := ""
		if fileOK {
			path, ok := file.(string)
			if !ok {
				return nil, nil, config.Invalid()
			}
			fingerprint, e = nodeCertificateThumbprint(path)
			if e != nil {
				return nil, nil, e
			}
		} else {
			fingerprint, ok = thumb.(string)
			if !ok || !nodeThumbprint(fingerprint) {
				return nil, nil, config.Invalid()
			}
		}
		bindingsRaw, ok := entry["dataset_bindings"].(map[string]any)
		if !ok || len(bindingsRaw) == 0 {
			return nil, nil, config.Invalid()
		}
		bindings := map[string]map[string]any{}
		for name, binding := range bindingsRaw {
			m, ok := binding.(map[string]any)
			if !ok || domain.ValidateIdentifier(name) != nil {
				return nil, nil, config.Invalid()
			}
			bindings[name] = domain.CloneMap(m)
		}
		resources := map[string]int64{"cpu_millicores": 1000, "memory_bytes": 1 << 30, "disk_bytes": 1 << 30}
		if raw, ok := entry["resources"]; ok {
			m, ok := raw.(map[string]any)
			if !ok || config.Keys(m, []string{"cpu_millicores", "memory_bytes", "disk_bytes"}, nil) != nil {
				return nil, nil, config.Invalid()
			}
			for name := range resources {
				v, e := config.Int(m[name], 1, 1<<50)
				if e != nil {
					return nil, nil, e
				}
				resources[name] = v
			}
		}
		enabled, e := config.GetBool(entry, "enabled", true)
		if e != nil {
			return nil, nil, e
		}
		node := participants.ApprovedNode{NodeID: id, CertificateThumbprint: fingerprint, DatasetBindings: bindings, Resources: resources, Enabled: enabled}
		if e = node.Validate(); e != nil {
			return nil, nil, e
		}
		approved = append(approved, node)
		endpoint, e := config.GetString(entry, "endpoint", "")
		if e != nil {
			return nil, nil, e
		}
		ca, e := config.GetString(entry, "ca_file", "")
		if e != nil || ca == "" {
			return nil, nil, config.Invalid()
		}
		clients[id] = participants.ClientConfig{Endpoint: endpoint, CAFile: ca, CertificateFile: certificate, KeyFile: key}
	}
	return approved, clients, nil
}
func ComposeParticipants(ctx context.Context, services *Services) error {
	values, e := services.Settings.Section("participants", false)
	if e != nil || len(values) == 0 {
		return e
	}
	if services.Provisioner == nil || services.Broker == nil || services.Settings.Workload == nil || services.Settings.Workload.PrivateKey == "" {
		return config.Invalid()
	}
	nodes, clientConfig, e := participantNodeApprovals(services.Settings)
	if e != nil {
		return e
	}
	dispatcher, e := participants.NewDispatchClient(clientConfig)
	if e != nil {
		return e
	}
	success := false
	defer func() {
		if !success {
			dispatcher.Close()
		}
	}()
	ca, e := services.Settings.Section("provisioner", true)
	if e != nil {
		return e
	}
	certificate, e := config.GetString(ca, "client_ca_certificate", "")
	if e != nil || certificate == "" {
		return config.Invalid()
	}
	key, e := config.GetString(ca, "client_ca_key", "")
	if e != nil || key == "" {
		return config.Invalid()
	}
	issuer, e := certificates.NewIssuer(certificates.Config{CACertificateFile: certificate, CAPrivateKeyFile: key, Clock: services.Now})
	if e != nil {
		return e
	}
	p := services.Provisioner
	hooks := participants.Hooks{
		WorkloadIssuer: services.Settings.Workload.Issuer, StoragePoolID: p.StoragePoolID,
		Snapshot: func(ctx context.Context, job map[string]any, spec domain.JobSpec) (participants.Snapshot, error) {
			snapshot, e := p.Snapshot(ctx, job)
			if e != nil {
				return participants.Snapshot{}, e
			}
			return participants.Snapshot{Root: snapshot.Path, Manifest: snapshot.Manifest}, nil
		},
		SpaceID: p.OwnedSpace, Image: p.Image,
		SourceLimits: func(ctx context.Context, spec domain.JobSpec) (map[string]any, error) {
			bounds, e := p.SourceBounds(ctx, map[string]any{"spec_json": spec.Map()})
			if e != nil {
				return nil, e
			}
			out := map[string]any{}
			for k, v := range bounds {
				out[k] = v
			}
			return out, nil
		},
		SecretOptions: p.ExternalSecretOptions,
		Reconciliation: func(ctx context.Context, jobID, component string, epoch int64) ([]map[string]any, error) {
			rows, e := p.ReconciliationDirectives(ctx, jobID, component, epoch)
			if e != nil {
				return nil, e
			}
			out := make([]map[string]any, len(rows))
			for i, row := range rows {
				m, ok := row.(map[string]any)
				if !ok {
					return nil, domain.Err(409, "invalid_reconciliation_directive")
				}
				out[i] = m
			}
			return out, nil
		},
		CreateGrant: func(ctx context.Context, space string, body map[string]any, key string) (map[string]any, error) {
			path, e := exchange.Path(space, "/workload-grants")
			if e != nil {
				return nil, e
			}
			return p.Exchange.Request(ctx, "POST", path, body, map[string]string{"Idempotency-Key": key}, nil)
		},
		GetGrant: p.ExchangeGrant,
		AppendLogs: func(ctx context.Context, actor participants.Actor, resourceID, nodeID string, receipt map[string]any) (map[string]any, error) {
			raw, e := domain.CanonicalJSON(receipt)
			if e != nil {
				return nil, domain.Err(422, "invalid_log_receipt")
			}
			value, e := artifacts.DecodeLogReceipt(raw)
			if e != nil {
				return nil, e
			}
			logs := &artifacts.LogService{DB: services.DB, Clock: services.Now}
			return logs.AppendExternalLogs(ctx, artifacts.LogIdentity{JobID: actor.JobID, AttemptID: actor.AttemptID, ComponentID: actor.ComponentID, Epoch: actor.Epoch}, value, resourceID, nodeID)
		},
	}
	hooks.BuiltArtifacts = func(ctx context.Context, actor participants.Actor, spec domain.JobSpec) (map[string]any, error) {
		manifest, e := participantBuildManifest(ctx, services, actor)
		if e != nil {
			return nil, e
		}
		return buildworker.ProductManifestMap(manifest), nil
	}
	hooks.BuildAccessValid = func(ctx context.Context, actor participants.Actor) bool {
		return participantBuildAccess(ctx, services, actor)
	}
	hooks.OpenBuildProduct = func(ctx context.Context, actor participants.Actor, name string) (*participants.SourceFile, error) {
		manifest, e := participantBuildManifest(ctx, services, actor)
		if e != nil {
			return nil, e
		}
		expected, ok := manifest[name]
		if !ok {
			return nil, domain.Err(404, "participant_build_product_not_found")
		}
		job, e := services.DB.One(ctx, "SELECT * FROM jm_jobs WHERE id=?", actor.JobID)
		if e != nil {
			return nil, e
		}
		data, e := p.ReadBuildProduct(ctx, job, name, expected.SizeBytes)
		if e != nil {
			return nil, domain.Err(409, "external_build_changed")
		}
		hash := sha256.Sum256(data)
		if int64(len(data)) != expected.SizeBytes || hex.EncodeToString(hash[:]) != expected.SHA256 {
			return nil, domain.Err(409, "external_build_changed")
		}
		if !participantBuildAccess(ctx, services, actor) {
			return nil, domain.Err(404, "participant_assignment_not_found")
		}
		return participants.NewSourceFile(data), nil
	}
	service, e := participants.NewService(services.DB, nodes, hooks, services.Broker, issuer)
	if e != nil {
		return e
	}
	service.Clock = services.Now
	service.Dispatch = dispatcher.Dispatch
	services.Participants = service
	if services.Controller != nil {
		services.Controller.Participants = service
	}
	p.ExternalCleanup = service.PurgeJob
	if services.PublicationObserver != nil {
		services.PublicationObserver.ExternalStateReader = controller.PublicationStateReaderFunc(service.ReadPublicationState)
	}
	services.CloseCallbacks = append(services.CloseCallbacks, func() error { service.Close(); dispatcher.Close(); return nil })
	success = true
	return nil
}
func participantBuildAccess(ctx context.Context, services *Services, actor participants.Actor) bool {
	return services.Participants != nil && actor.ExpiresAt > services.Now().Unix() && services.Participants.SourceAccessValid(ctx, actor)
}
func participantBuildManifest(ctx context.Context, services *Services, actor participants.Actor) (map[string]buildworker.Descriptor, error) {
	if !actor.HasScope("assignment") {
		return nil, domain.Err(403, "node_scope_required")
	}
	if actor.ExpiresAt <= services.Now().Unix() {
		return nil, domain.Err(401, "node_grant_expired")
	}
	if !participantBuildAccess(ctx, services, actor) {
		return nil, domain.Err(404, "participant_assignment_not_found")
	}
	job, e := services.DB.One(ctx, "SELECT * FROM jm_jobs WHERE id=?", actor.JobID)
	if e != nil {
		return nil, e
	}
	if job == nil {
		return nil, domain.Err(404, "participant_assignment_not_found")
	}
	spec, e := domain.JobSpecFromMap(nodeObject(job["spec_json"]))
	if e != nil {
		return nil, e
	}
	node, ok := services.Participants.Nodes[actor.NodeID]
	if !ok {
		return nil, domain.Err(404, "participant_assignment_not_found")
	}
	manifest, e := services.Provisioner.BuildManifest(ctx, job)
	if e != nil {
		return nil, domain.Err(409, "external_build_not_ready")
	}
	limit := node.Resources["disk_bytes"]
	if limit > 256<<20 {
		limit = 256 << 20
	}
	parsed, e := buildworker.ParseManifest(manifest, limit)
	if e != nil {
		return nil, e
	}
	hasBuild := false
	for _, c := range spec.Components {
		if c.Role == "build" {
			hasBuild = true
		}
	}
	if len(parsed) > 0 && !hasBuild {
		return nil, domain.Err(409, "external_build_not_approved")
	}
	if len(parsed) == 0 && hasBuild {
		return nil, domain.Err(409, "external_build_not_ready")
	}
	if !participantBuildAccess(ctx, services, actor) {
		return nil, domain.Err(404, "participant_assignment_not_found")
	}
	return parsed, nil
}
func configureParticipantAPI(options *httpapi.Options, services *Services) error {
	if services.Participants == nil {
		return nil
	}
	service := services.Participants
	options.ParticipantEnroll = service.Enroll
	options.ParticipantEnrollment = service.GetEnrollment
	options.ParticipantCall = func(ctx context.Context, action string, actor httpapi.ExecutionActor, id executor.ExecutionIdentity, body map[string]any) (map[string]any, error) {
		if !sameActorIdentity(actor, id) {
			return nil, domain.Err(403, "foreign_participant_assignment")
		}
		p := nodePrincipal(actor)
		switch action {
		case "plan":
			return service.AssignmentPlan(ctx, p)
		case "control":
			return service.ControlPlan(ctx, p)
		case "heartbeat":
			phase := nodeString(body["phase"])
			if phase == "" {
				phase = "running"
			}
			var round *int64
			if body["current_round"] != nil {
				n, ok := nodeInteger(body["current_round"])
				if !ok {
					return nil, domain.Err(422, "invalid_request")
				}
				round = &n
			}
			return service.Heartbeat(ctx, p, phase, round)
		case "assignment":
			return service.Assignment(ctx, p, nodeString(body["certificate_thumbprint"]), nodeString(body["proxy_id"]))
		case "certificate":
			return service.IssueCertificate(ctx, p, nodeString(body["csr_pem"]), nodeString(body["space_id"]), nodeString(body["principal_id"]))
		case "credentials":
			return service.Credentials(ctx, p)
		case "stopped":
			return service.ConfirmStopped(ctx, p, body["termination_confirmed"] == true, body["never_started"] == true)
		case "logs":
			return service.AppendLogs(ctx, p, body)
		case "purge-plan":
			return service.PurgePlan(ctx, p)
		case "purged":
			return service.ConfirmPurged(ctx, p, body["confirmed"] == true)
		}
		return nil, domain.Err(404, "not_found")
	}
	options.ParticipantOpen = func(ctx context.Context, action string, actor httpapi.ExecutionActor, path string) (*httpapi.StreamFile, error) {
		var f *participants.SourceFile
		var e error
		switch action {
		case "source":
			f, e = service.OpenSource(ctx, nodePrincipal(actor), path)
		case "build-products":
			f, e = service.OpenBuildProduct(ctx, nodePrincipal(actor), path)
		default:
			return nil, domain.Err(404, "not_found")
		}
		if e != nil {
			return nil, e
		}
		return &httpapi.StreamFile{Reader: f.ReadCloser, SizeBytes: f.SizeBytes, SHA256: f.SHA256}, nil
	}
	options.ParticipantAccessValid = func(ctx context.Context, action string, actor httpapi.ExecutionActor) (bool, error) {
		if actor.ExpiresAt <= services.Now().Unix() {
			return false, nil
		}
		switch action {
		case "source":
			return service.SourceAccessValid(ctx, nodePrincipal(actor)), nil
		case "build-products":
			return service.BuildAccessValid(ctx, nodePrincipal(actor)), nil
		}
		return false, domain.Err(404, "not_found")
	}
	return nil
}

func RunParticipantAgent(ctx context.Context, settings config.Settings, args Arguments) error {
	var agent *participants.Agent
	nodeToken := func(ctx context.Context, id executor.ExecutionIdentity, operation string) (string, error) {
		if agent == nil {
			return "", domain.Err(503, "external_node_grant_unavailable")
		}
		return agent.NodeToken(ctx, id)
	}
	workloadToken := func(ctx context.Context, id executor.ExecutionIdentity, audience string) (string, error) {
		if agent == nil {
			return "", domain.Err(503, "external_node_grant_unavailable")
		}
		return agent.DelegatedToken(ctx, id, audience)
	}
	env, e := createStandaloneNode(ctx, settings, true, nodeToken, workloadToken)
	if e != nil {
		return e
	}
	defer env.Close()
	values := env.AgentValues
	client, e := participants.NewManagerClient(participants.ClientConfig{Endpoint: nodeString(values["manager_endpoint"]), CAFile: nodeString(values["manager_ca_file"]), CertificateFile: nodeString(values["node_certificate"]), KeyFile: nodeString(values["node_key"])})
	if e != nil {
		return e
	}
	defer client.Close()
	fingerprint, e := nodeCertificateThumbprint(nodeString(values["node_certificate"]))
	if e != nil {
		return e
	}
	cfg := participants.AgentConfig{NodeID: env.NodeID, NodeCertificateThumbprint: fingerprint, LedgerPath: nodeString(env.Values["ledger_path"]), Root: env.Materializer.Config.Root}
	cfg.ProxyStop = func(ctx context.Context, id executor.ExecutionIdentity, confirmed bool) (bool, error) {
		if !confirmed {
			return false, domain.Err(409, "runtime_active")
		}
		return env.stopPrivate(ctx, id)
	}
	cfg.PurgePrivate = func(ctx context.Context, id executor.ExecutionIdentity, assignment *participants.CleanupAssignment) (bool, error) {
		if assignment == nil {
			return false, domain.Err(409, "participant_assignment_not_found")
		}
		return env.purgePrivate(ctx, id)
	}
	agent, e = participants.NewAgent(cfg, client, env.Materializer, env.Runtime, env.Broker)
	if e != nil {
		return e
	}
	defer agent.Close()
	allowlist, e := nodeStrings(values["manager_certificate_thumbprints"])
	if e != nil || len(allowlist) == 0 {
		return config.Invalid()
	}
	for _, thumb := range allowlist {
		if !nodeThumbprint(thumb) {
			return config.Invalid()
		}
	}
	if e = agent.StartLogPolling(ctx, time.Second); e != nil {
		return e
	}
	boundaries, e := settings.Section("boundaries", true)
	if e != nil {
		return e
	}
	boundary, ok := boundaries["participants"].(map[string]any)
	if !ok {
		return config.Invalid()
	}
	boundary, e = normalizedNodeBoundary(boundary, 8443)
	if e != nil {
		return e
	}
	return RunMTLS(ctx, settings, args, agent.Handler(allowlist), boundary)
}
