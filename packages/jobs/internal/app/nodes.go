package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/node"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/provision"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/resources"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/secrets"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/source"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/transfer"
)

func nodeObject(value any) map[string]any {
	m, _ := value.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}
func nodeString(value any) string { s, _ := value.(string); return s }
func nodeInteger(value any) (int64, bool) {
	switch n := value.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case json.Number:
		if strings.ContainsAny(string(n), ".eE") {
			return 0, false
		}
		i, e := n.Int64()
		return i, e == nil
	}
	return 0, false
}
func nodeNumber(value any) int64 { n, _ := nodeInteger(value); return n }
func nodeSame(a, b any) bool {
	x, e := domain.CanonicalJSON(a)
	if e != nil {
		return false
	}
	y, e := domain.CanonicalJSON(b)
	return e == nil && string(x) == string(y)
}
func nodeStrings(value any) ([]string, error) {
	if list, ok := value.([]string); ok {
		return append([]string{}, list...), nil
	}
	list, ok := value.([]any)
	if !ok {
		return nil, config.Invalid()
	}
	out := make([]string, len(list))
	for i, v := range list {
		var good bool
		out[i], good = v.(string)
		if !good {
			return nil, config.Invalid()
		}
	}
	return out, nil
}
func nodeCertificateThumbprint(path string) (string, error) { return node.CertificateThumbprint(path) }
func nodeThumbprint(value string) bool {
	b, e := base64.RawURLEncoding.DecodeString(value)
	return e == nil && len(b) == 32 && len(value) == 43 && base64.RawURLEncoding.EncodeToString(b) == value
}

type registeredNodeConfiguration struct {
	Endpoints         map[string]node.NodeEndpoint
	Approvals         map[string]node.ApprovedManagedNode
	ManagerThumbprint string
}

func registeredNodeConfig(settings config.Settings) (registeredNodeConfiguration, error) {
	out := registeredNodeConfiguration{Endpoints: map[string]node.NodeEndpoint{}, Approvals: map[string]node.ApprovedManagedNode{}}
	values, e := settings.Section("nodes", true)
	if e != nil {
		return out, e
	}
	if e = config.Keys(values, []string{"client_certificate", "client_key", "endpoints"}, nil); e != nil {
		return out, e
	}
	certificate, e := config.GetString(values, "client_certificate", "")
	if e != nil || certificate == "" {
		return out, config.Invalid()
	}
	key, e := config.GetString(values, "client_key", "")
	if e != nil || key == "" {
		return out, config.Invalid()
	}
	if _, e = config.ReadSecret(key); e != nil {
		return out, e
	}
	out.ManagerThumbprint, e = node.CertificateThumbprint(certificate)
	if e != nil {
		return out, e
	}
	entries, ok := values["endpoints"].(map[string]any)
	if !ok || len(entries) == 0 {
		return out, config.Invalid()
	}
	for id, raw := range entries {
		if domain.ValidateIdentifier(id) != nil {
			return out, config.Invalid()
		}
		entry, ok := raw.(map[string]any)
		if !ok {
			return out, config.Invalid()
		}
		if e = config.Keys(entry, []string{"origin", "ca_file", "pool_id", "registration_id"}, []string{"certificate_file", "certificate_thumbprint", "enabled", "dataset_bindings"}); e != nil {
			return out, e
		}
		file, hasFile := entry["certificate_file"]
		thumb, hasThumb := entry["certificate_thumbprint"]
		if hasFile == hasThumb {
			return out, config.Invalid()
		}
		enabled, e := config.GetBool(entry, "enabled", true)
		if e != nil {
			return out, e
		}
		pool, e := config.GetString(entry, "pool_id", "")
		if e != nil || domain.ValidateIdentifier(pool) != nil {
			return out, config.Invalid()
		}
		registration, e := config.GetString(entry, "registration_id", "")
		if e != nil || domain.ValidateIdentifier(registration) != nil {
			return out, config.Invalid()
		}
		origin, e := config.GetString(entry, "origin", "")
		if e != nil {
			return out, e
		}
		ca, e := config.GetString(entry, "ca_file", "")
		if e != nil || ca == "" {
			return out, config.Invalid()
		}
		fingerprint := ""
		if hasFile {
			path, ok := file.(string)
			if !ok {
				return out, config.Invalid()
			}
			fingerprint, e = node.CertificateThumbprint(path)
			if e != nil {
				return out, e
			}
		} else {
			fingerprint, ok = thumb.(string)
			if !ok || !nodeThumbprint(fingerprint) {
				return out, config.Invalid()
			}
		}
		approval := node.ApprovedManagedNode{NodeID: id, PoolID: pool, RegistrationID: registration, CertificateThumbprint: fingerprint, Enabled: enabled}
		if e = approval.Validate(); e != nil {
			return out, e
		}
		if !enabled {
			continue
		}
		endpoint := node.NodeEndpoint{NodeID: id, Origin: origin, CAFile: ca, ClientCertificate: certificate, ClientKey: key}.Defaults()
		if e = endpoint.Validate(); e != nil {
			return out, e
		}
		out.Endpoints[id] = endpoint
		out.Approvals[id] = approval
	}
	if len(out.Endpoints) == 0 {
		return out, config.Invalid()
	}
	return out, nil
}

type admittedNode struct {
	Job, Attempt, Allocation map[string]any
	Route                    node.NodeRoute
	Spec                     domain.JobSpec
}

func nodeAdmission(ctx context.Context, services *Services, id executor.ExecutionIdentity, poolID string) (admittedNode, error) {
	var out admittedNode
	if id.Validate() != nil {
		return out, domain.Err(409, "invalid_identity")
	}
	e := services.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id=?", id.JobID)
		if e != nil {
			return e
		}
		attempt, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE id=?", id.AttemptID)
		if e != nil {
			return e
		}
		rows, e := tx.All(ctx, "SELECT * FROM jm_allocations WHERE job_id=? AND attempt_id=? AND component_id=? AND epoch=?", id.JobID, id.AttemptID, id.ComponentID, id.Epoch)
		if e != nil {
			return e
		}
		if job == nil || attempt == nil || attempt["job_id"] != id.JobID || nodeNumber(attempt["epoch"]) != id.Epoch || len(rows) != 1 {
			return domain.Err(409, "assignment_unavailable")
		}
		allocation := rows[0]
		pool, e := tx.One(ctx, "SELECT * FROM jm_pools WHERE id=?", allocation["pool_id"])
		if e != nil {
			return e
		}
		if pool == nil || (poolID != "" && pool["id"] != poolID) {
			return domain.Err(409, "pool_mismatch")
		}
		nodeID := nodeString(nodeObject(allocation["details_json"])["node_id"])
		if nodeID == "" {
			if allocation["released_at"] != nil {
				return domain.Err(409, "assignment_unavailable")
			}
			nodeID = nodeString(pool["node_id"])
		}
		raw, e := domain.CanonicalJSON(job["spec_json"])
		if e != nil {
			return domain.Err(409, "assignment_conflict")
		}
		snapshot, e := domain.DecodeJobSpec(raw)
		if e != nil {
			return domain.Err(409, "assignment_conflict")
		}
		digest, e := snapshot.Digest()
		if e != nil || digest != job["spec_hash"] {
			return domain.Err(409, "assignment_conflict")
		}
		var component *domain.ComponentSpec
		for _, c := range snapshot.Components {
			if c.ComponentID == id.ComponentID {
				copy := c
				component = &copy
			}
		}
		if component == nil || component.Resources.PoolID != allocation["pool_id"] {
			return domain.Err(409, "assignment_conflict")
		}
		limits := executor.ResourceLimits{CPUMillis: nodeNumber(allocation["cpu_millicores"]), MemoryBytes: nodeNumber(allocation["memory_bytes"]), DiskBytes: nodeNumber(allocation["disk_bytes"]), GPUs: nodeNumber(allocation["gpu_count"])}.Defaults()
		if component.Resources.CPUMillicores != limits.CPUMillis || component.Resources.MemoryBytes != limits.MemoryBytes || component.Resources.DiskBytes != limits.DiskBytes || component.Resources.GPUCount != limits.GPUs {
			return domain.Err(409, "invalid_resources")
		}
		target := node.NodeRoute{NodeID: nodeID, PoolID: nodeString(pool["id"]), Resources: limits}
		if e = target.Validate(); e != nil {
			return e
		}
		out = admittedNode{Job: job, Attempt: attempt, Allocation: allocation, Route: target, Spec: snapshot}
		return nil
	})
	return out, e
}
func prepaidRemoteSource(ctx context.Context, services *Services, a admittedNode, id executor.ExecutionIdentity) (map[string]int64, error) {
	rows, e := services.DB.All(ctx, "SELECT * FROM jm_provisioning_resources WHERE job_id=? AND component_id=? AND kind=? AND deleted_at IS NULL", id.JobID, id.ComponentID, "remote_auxiliary")
	if e != nil {
		return nil, e
	}
	digest, e := a.Spec.Digest()
	if e != nil {
		return nil, e
	}
	var shared, private []map[string]any
	for _, row := range rows {
		d := nodeObject(row["details_json"])
		if d["node_id"] != a.Route.NodeID || d["pool_id"] != a.Route.PoolID || d["spec_digest"] != digest || nodeNumber(d["retention_charged_bytes"]) <= 0 || d["retention_charge_released"] == true {
			continue
		}
		if d["scope"] == "shared" {
			shared = append(shared, d)
		}
		if d["scope"] == "attempt_private" && nodeNumber(d["attempt_number"]) == nodeNumber(a.Attempt["number"]) {
			private = append(private, d)
		}
	}
	if len(shared) != 1 || len(private) != 1 {
		return nil, domain.Err(409, "source_capacity_not_reserved")
	}
	m := nodeObject(shared[0]["source_limits"])
	if len(m) != 4 {
		return nil, domain.Err(409, "source_capacity_not_reserved")
	}
	bounds := map[string]int64{}
	for _, key := range []string{"max_bytes", "max_files", "max_git_bytes", "max_git_files"} {
		n, ok := nodeInteger(m[key])
		if !ok || n < 1 || n > 1<<40 {
			return nil, domain.Err(409, "source_capacity_not_reserved")
		}
		bounds[key] = n
	}
	return bounds, nil
}

func ComposeNodes(ctx context.Context, services *Services, withController bool) error {
	values, e := services.Settings.Section("nodes", false)
	if e != nil {
		return e
	}
	localValues, e := services.Settings.Section("node", false)
	if e != nil {
		return e
	}
	if withController && len(localValues) > 0 {
		services.LocalNode, e = CreateNodeAgent(ctx, services.Settings, services.DB)
		if e != nil {
			return e
		}
	}
	if len(values) == 0 {
		if withController && services.LocalNode == nil {
			return config.Invalid()
		}
		if services.LocalNode != nil {
			services.Node = services.LocalNode
		} else {
			services.Node = nil
		}
		return nil
	}
	if services.Broker == nil || services.Settings.Workload == nil || services.Settings.Workload.PrivateKey == "" {
		return config.Invalid()
	}
	cfg, e := registeredNodeConfig(services.Settings)
	if e != nil {
		return e
	}
	route := func(ctx context.Context, id executor.ExecutionIdentity, pool string) (node.NodeRoute, error) {
		a, e := nodeAdmission(ctx, services, id, pool)
		return a.Route, e
	}
	remote, e := node.NewRemoteExecutor(node.RemoteConfig{
		Endpoints: cfg.Endpoints, Route: route,
		AssignmentProvider: func(ctx context.Context, spec executor.ExecutionSpec, target node.NodeRoute) (node.RemoteAssignment, error) {
			a, e := nodeAdmission(ctx, services, spec.Identity, target.PoolID)
			if e != nil {
				return node.RemoteAssignment{}, e
			}
			if a.Route != target || a.Allocation["released_at"] != nil {
				return node.RemoteAssignment{}, domain.Err(409, "assignment_conflict")
			}
			if services.Provisioner == nil {
				return node.RemoteAssignment{}, domain.Err(503, "configuration_unavailable")
			}
			image, e := services.Provisioner.Image(ctx, a.Spec)
			if e != nil {
				return node.RemoteAssignment{}, e
			}
			if image != spec.ImageDigest {
				return node.RemoteAssignment{}, domain.Err(409, "image_not_pinned")
			}
			bounds, e := prepaidRemoteSource(ctx, services, a, spec.Identity)
			if e != nil {
				return node.RemoteAssignment{}, e
			}
			return node.RemoteAssignment{Identity: spec.Identity, NodeID: target.NodeID, PoolID: target.PoolID, Resources: target.Resources, JobSpec: a.Spec, ImageDigest: image, LeaseSeconds: spec.LeaseSeconds, Deadline: spec.Deadline, SourceLimits: bounds}, nil
		},
		TokenProvider: func(ctx context.Context, target node.NodeRoute, id executor.ExecutionIdentity, scope string) (string, error) {
			a, e := nodeAdmission(ctx, services, id, target.PoolID)
			if e != nil {
				return "", e
			}
			registration, ok := cfg.Approvals[a.Route.NodeID]
			if a.Route != target || !ok || registration.PoolID != target.PoolID {
				return "", domain.Err(409, "node_not_approved")
			}
			active := scope == "reserve" || scope == "start" || scope == "renew" || scope == "assignment" || scope == "heartbeat"
			if active {
				deadline, ok := store.Time(a.Job["deadline_at"])
				if nodeNumber(a.Job["epoch"]) != id.Epoch || nodeNumber(a.Attempt["number"]) != nodeNumber(a.Job["current_attempt"]) || a.Allocation["released_at"] != nil || !nodeActive(nodeString(a.Job["state"])) || !ok || !services.Now().Before(deadline) {
					return "", domain.Err(409, "execution_grant_revoked")
				}
			} else {
				switch scope {
				case "inspect", "stop", "collect", "release", "purge", "logs":
				default:
					return "", domain.Err(409, "invalid_node_scope")
				}
			}
			if services.ManagedNodes == nil {
				return "", domain.Err(503, "node_grant_unavailable")
			}
			resources := map[string]any{"cpu_millicores": target.Resources.CPUMillis, "memory_bytes": target.Resources.MemoryBytes, "disk_bytes": target.Resources.DiskBytes}
			return services.ManagedNodes.IssueControlToken(ctx, id, target.NodeID, target.PoolID, scope, cfg.ManagerThumbprint, resources)
		},
		PreparedProvider: func(ctx context.Context, id executor.ExecutionIdentity) (node.PreparedExecution, error) {
			a, e := nodeAdmission(ctx, services, id, "")
			if e != nil {
				return node.PreparedExecution{}, e
			}
			if services.Provisioner == nil {
				return node.PreparedExecution{}, domain.Err(503, "configuration_unavailable")
			}
			configuration, e := services.Provisioner.PreparedComponent(ctx, a.Job, a.Attempt, id.ComponentID)
			if e != nil {
				return node.PreparedExecution{}, e
			}
			products, e := services.Provisioner.PreparedBuildProducts(ctx, a.Job, a.Attempt, id.ComponentID)
			if e != nil {
				return node.PreparedExecution{}, e
			}
			var binding map[string]any
			for _, component := range a.Spec.Components {
				if component.ComponentID == id.ComponentID && component.Role != "build" {
					if services.Provisioner.ExecutionBindings == nil {
						return node.PreparedExecution{}, domain.Err(503, "configuration_unavailable")
					}
					binding, e = services.Provisioner.ExecutionBindings(ctx, a.Job, a.Attempt, component, nodeString(configuration["space_id"]), services.Provisioner.Principal(id.JobID, id.ComponentID, component.ParticipantID))
					if e != nil {
						return node.PreparedExecution{}, e
					}
				}
			}
			return node.PreparedExecution{RuntimeConfig: configuration, ExecutionBinding: binding, BuildProducts: products}, nil
		},
	})
	if e != nil {
		return e
	}
	services.Remote = remote
	services.Node = &RegisteredExecutor{Remote: remote, Local: services.LocalNode, Route: route, Endpoints: cfg.Endpoints}
	services.CloseCallbacks = append(services.CloseCallbacks, func() error { remote.Close(); return nil })
	return nil
}
func nodeActive(state string) bool {
	return state == "PROVISIONING" || state == "STARTING" || state == "RUNNING"
}

func ComposeManagedNodes(ctx context.Context, services *Services) error {
	values, e := services.Settings.Section("nodes", false)
	if e != nil || len(values) == 0 {
		return e
	}
	if services.Provisioner == nil || services.Broker == nil || services.Settings.Workload == nil || services.Settings.Workload.PrivateKey == "" {
		return config.Invalid()
	}
	cfg, e := registeredNodeConfig(services.Settings)
	if e != nil {
		return e
	}
	p, e := services.Settings.Section("provisioner", true)
	if e != nil {
		return e
	}
	certificate, e := config.GetString(p, "client_ca_certificate", "")
	if e != nil || certificate == "" {
		return config.Invalid()
	}
	key, e := config.GetString(p, "client_ca_key", "")
	if e != nil || key == "" {
		return config.Invalid()
	}
	issuer, e := certificates.NewIssuer(certificates.Config{CACertificateFile: certificate, CAPrivateKeyFile: key, Clock: services.Now})
	if e != nil {
		return e
	}
	service, e := node.NewAssignmentService(services.DB, services.Broker, node.AssignmentConfig{
		RegisteredNodes: cfg.Approvals, ManagerCertificateThumbprint: cfg.ManagerThumbprint, Provisioner: services.Provisioner, Clock: services.Now,
		IssueCertificate: func(ctx context.Context, csr string, id executor.ExecutionIdentity, space string, deadline time.Time) (map[string]any, error) {
			issued, e := issuer.Issue([]byte(csr), certificates.Binding{JobID: id.JobID, AttemptID: id.AttemptID, ComponentID: id.ComponentID, Epoch: id.Epoch, SpaceID: space}, deadline)
			if e != nil {
				return nil, e
			}
			return map[string]any{"certificate_pem": issued.CertificatePEM, "certificate_thumbprint": issued.CertificateThumbprint, "expires_at": issued.ExpiresAt}, nil
		},
	})
	if e != nil {
		return e
	}
	services.ManagedNodes = service
	return nil
}
func executionActor(p exchange.NodePrincipal) httpapi.ExecutionActor {
	return httpapi.ExecutionActor{ID: p.ID, Subject: p.Subject, NodeID: p.NodeID, PoolID: p.PoolID, JobID: p.JobID, AttemptID: p.AttemptID, ComponentID: p.ComponentID, GrantID: p.GrantID, CertificateThumbprint: p.CertificateThumbprint, Epoch: p.Epoch, IssuedAt: p.IssuedAt, ExpiresAt: p.ExpiresAt, Scopes: append([]string{}, p.Scopes...), Resources: domain.CloneMap(p.Resources)}
}
func nodePrincipal(p httpapi.ExecutionActor) exchange.NodePrincipal {
	return exchange.NodePrincipal{ID: p.ID, Subject: p.Subject, NodeID: p.NodeID, PoolID: p.PoolID, JobID: p.JobID, AttemptID: p.AttemptID, ComponentID: p.ComponentID, GrantID: p.GrantID, CertificateThumbprint: p.CertificateThumbprint, Epoch: p.Epoch, IssuedAt: p.IssuedAt, ExpiresAt: p.ExpiresAt, Scopes: append([]string{}, p.Scopes...), Resources: domain.CloneMap(p.Resources)}
}
func CurrentNodeGrant(ctx context.Context, services *Services, actor exchange.NodePrincipal) (bool, error) {
	if services.DB == nil || actor.GrantID == "" {
		return false, nil
	}
	// Select the authority from the persisted grant kind. A refusal from that
	// authority is final; authorization errors never trigger another validator.
	resource, e := services.DB.One(ctx, "SELECT kind FROM jm_provisioning_resources WHERE id=?", actor.GrantID)
	if e != nil {
		return false, e
	}
	if resource != nil && (resource["kind"] == "external_enrollment" || resource["kind"] == "external_execution") {
		if actor.PoolID != "external" || services.Participants == nil {
			return false, nil
		}
		return services.Participants.CheckNodeGrant(ctx, actor), nil
	}
	allocation, e := services.DB.One(ctx, "SELECT * FROM jm_allocations WHERE id=? AND job_id=? AND attempt_id=? AND component_id=? AND epoch=? AND pool_id=?", actor.GrantID, actor.JobID, actor.AttemptID, actor.ComponentID, actor.Epoch, actor.PoolID)
	if e != nil {
		return false, e
	}
	if allocation == nil {
		return false, nil
	}
	if services.ManagedNodes != nil {
		registered, ok := services.ManagedNodes.Config.RegisteredNodes[actor.NodeID]
		if ok && registered.PoolID == actor.PoolID {
			return services.ManagedNodes.CheckNodeGrant(ctx, actor)
		}
	}
	local, e := services.Settings.Section("node", false)
	if e != nil {
		return false, e
	}
	if local["node_id"] != actor.NodeID || local["pool_id"] != actor.PoolID || services.Controller == nil {
		return false, nil
	}
	valid, e := services.Controller.CheckAssignment(ctx, actor.NodeID, actor.PoolID, actor.JobID, actor.AttemptID, actor.ComponentID, actor.Epoch)
	if e != nil || !valid {
		return false, e
	}
	if allocation["released_at"] != nil || nodeNumber(allocation["gpu_count"]) != 0 {
		return false, nil
	}
	for _, key := range []string{"cpu_millicores", "memory_bytes", "disk_bytes"} {
		n, ok := nodeInteger(actor.Resources[key])
		if !ok || n != nodeNumber(allocation[key]) {
			return false, nil
		}
	}
	if value, ok := actor.Resources["gpu_uuids"]; ok {
		list, e := nodeStrings(value)
		if e != nil || len(list) > 0 {
			return false, nil
		}
	}
	return true, nil
}
func sameActorIdentity(actor httpapi.ExecutionActor, id executor.ExecutionIdentity) bool {
	return actor.JobID == id.JobID && actor.AttemptID == id.AttemptID && actor.ComponentID == id.ComponentID && actor.Epoch == id.Epoch
}
func ConfigureNodeAPI(options *httpapi.Options, services *Services) error {
	if services.Broker != nil {
		authenticate := func(ctx context.Context, authorization, peer string) (httpapi.ExecutionActor, error) {
			p, e := services.Broker.AuthenticateNode(ctx, authorization, peer, func(ctx context.Context, p exchange.NodePrincipal) (bool, error) {
				return CurrentNodeGrant(ctx, services, p)
			})
			return executionActor(p), e
		}
		options.NodeAuthenticate = authenticate
		options.ManagedAuthenticate = authenticate
	}
	if services.Controller != nil {
		options.CheckAssignment = func(ctx context.Context, nodeID, pool string, id executor.ExecutionIdentity) (bool, error) {
			return services.Controller.CheckAssignment(ctx, nodeID, pool, id.JobID, id.AttemptID, id.ComponentID, id.Epoch)
		}
		options.NodeCommand = func(ctx context.Context, action string, id executor.ExecutionIdentity, body map[string]any) (bool, error) {
			c := services.Controller
			switch action {
			case "ack":
				return c.AckAssignment(ctx, id.JobID, id.AttemptID, id.ComponentID, id.Epoch)
			case "heartbeat":
				return c.Heartbeat(ctx, id.JobID, id.AttemptID, id.ComponentID, id.Epoch)
			case "stopped":
				return c.StopConfirmation(ctx, id.JobID, id.AttemptID, id.ComponentID, id.Epoch)
			case "logs":
				entries, e := nodeStrings(body["entries"])
				if e != nil {
					return false, domain.Err(422, "invalid_request")
				}
				return c.AppendLogs(ctx, id.JobID, id.AttemptID, id.ComponentID, id.Epoch, strings.Join(entries, "\n"))
			case "progress":
				report := controller.ProgressReport{Phase: nodeString(body["phase"]), PublicationStatus: nodeString(body["publication_status"]), Readiness: nodeString(body["readiness"]), Metrics: map[string]float64{}}
				if value := body["current_round"]; value != nil {
					n, ok := nodeInteger(value)
					if !ok {
						return false, domain.Err(422, "invalid_request")
					}
					report.CurrentRound = &n
				}
				for key, v := range nodeObject(body["metrics"]) {
					var n float64
					switch value := v.(type) {
					case json.Number:
						var parseErr error
						n, parseErr = value.Float64()
						if parseErr != nil {
							return false, domain.Err(422, "invalid_request")
						}
					case int:
						n = float64(value)
					case float32:
						n = float64(value)
					case float64:
						n = value
					case int64:
						n = float64(value)
					default:
						return false, domain.Err(422, "invalid_request")
					}
					if math.IsNaN(n) || math.IsInf(n, 0) {
						return false, domain.Err(422, "invalid_request")
					}
					report.Metrics[key] = n
				}
				return c.Progress(ctx, id.JobID, id.AttemptID, id.ComponentID, id.Epoch, report)
			}
			return false, domain.Err(404, "not_found")
		}
	}
	if services.ManagedNodes != nil {
		options.ManagedBootstrap = services.ManagedNodes.Bootstrap
		options.ManagedCall = func(ctx context.Context, action string, actor httpapi.ExecutionActor, id executor.ExecutionIdentity, body map[string]any) (map[string]any, error) {
			if !sameActorIdentity(actor, id) {
				return nil, domain.Err(403, "foreign_node_assignment")
			}
			p := nodePrincipal(actor)
			switch action {
			case "plan":
				return services.ManagedNodes.Assignment(ctx, p)
			case "certificate":
				return services.ManagedNodes.IssueCertificate(ctx, p, nodeString(body["csr_pem"]), nodeString(body["space_id"]), nodeString(body["principal_id"]))
			case "credentials":
				return services.ManagedNodes.Credentials(ctx, p, nodeString(body["certificate_thumbprint"]), nodeString(body["audience"]))
			case "validate":
				scopes, e := nodeStrings(body["scopes"])
				if e != nil {
					return nil, domain.Err(422, "invalid_request")
				}
				return services.ManagedNodes.Validate(ctx, p, node.ValidationRequest{NodeID: nodeString(body["node_id"]), PoolID: nodeString(body["pool_id"]), GrantID: nodeString(body["grant_id"]), CertificateThumbprint: nodeString(body["certificate_thumbprint"]), Scopes: scopes, Resources: nodeObject(body["resources"])})
			}
			return nil, domain.Err(404, "not_found")
		}
	}
	return configureParticipantAPI(options, services)
}

// RegisteredExecutor always follows the durable placement. Availability cannot
// redirect a job to an unapproved node or substitute a local process.
type RegisteredExecutor struct {
	Remote    *node.RemoteExecutor
	Local     *executor.NodeAgent
	Route     func(context.Context, executor.ExecutionIdentity, string) (node.NodeRoute, error)
	Endpoints map[string]node.NodeEndpoint
}

func (r *RegisteredExecutor) selectExecutor(ctx context.Context, id executor.ExecutionIdentity, pool string) (controller.Executor, bool, error) {
	target, e := r.Route(ctx, id, pool)
	if e != nil {
		return nil, false, e
	}
	if r.Local != nil && target.NodeID == r.Local.NodeID && target.PoolID == r.Local.PoolID {
		return r.Local, false, nil
	}
	if r.Remote == nil {
		return nil, false, domain.Err(409, "node_not_approved")
	}
	if _, ok := r.Endpoints[target.NodeID]; !ok {
		return nil, false, domain.Err(409, "node_not_approved")
	}
	return r.Remote, true, nil
}
func (r *RegisteredExecutor) IsRemote(ctx context.Context, id executor.ExecutionIdentity) (bool, error) {
	_, remote, e := r.selectExecutor(ctx, id, "")
	return remote, e
}
func (r *RegisteredExecutor) Reserve(ctx context.Context, s executor.ExecutionSpec) (executor.Reservation, error) {
	x, _, e := r.selectExecutor(ctx, s.Identity, s.PoolID)
	if e != nil {
		return executor.Reservation{}, e
	}
	return x.Reserve(ctx, s)
}
func (r *RegisteredExecutor) Start(ctx context.Context, id executor.ExecutionIdentity) (executor.RuntimeObservation, error) {
	x, _, e := r.selectExecutor(ctx, id, "")
	if e != nil {
		return executor.RuntimeObservation{}, e
	}
	return x.Start(ctx, id)
}
func (r *RegisteredExecutor) Inspect(ctx context.Context, id executor.ExecutionIdentity) (executor.RuntimeObservation, error) {
	x, _, e := r.selectExecutor(ctx, id, "")
	if e != nil {
		return executor.RuntimeObservation{}, e
	}
	return x.Inspect(ctx, id)
}
func (r *RegisteredExecutor) Stop(ctx context.Context, id executor.ExecutionIdentity, grace int) (executor.RuntimeObservation, error) {
	x, _, e := r.selectExecutor(ctx, id, "")
	if e != nil {
		return executor.RuntimeObservation{}, e
	}
	return x.Stop(ctx, id, grace)
}
func (r *RegisteredExecutor) Renew(ctx context.Context, id executor.ExecutionIdentity) error {
	x, _, e := r.selectExecutor(ctx, id, "")
	if e != nil {
		return e
	}
	return x.Renew(ctx, id)
}
func (r *RegisteredExecutor) Collect(ctx context.Context, id executor.ExecutionIdentity) ([]executor.CollectedArtifact, error) {
	x, _, e := r.selectExecutor(ctx, id, "")
	if e != nil {
		return nil, e
	}
	return x.Collect(ctx, id)
}
func (r *RegisteredExecutor) Release(ctx context.Context, id executor.ExecutionIdentity) (bool, error) {
	x, _, e := r.selectExecutor(ctx, id, "")
	if e != nil {
		return false, e
	}
	return x.Release(ctx, id)
}
func (r *RegisteredExecutor) Purge(ctx context.Context, id executor.ExecutionIdentity) (bool, error) {
	x, _, e := r.selectExecutor(ctx, id, "")
	if e != nil {
		return false, e
	}
	return x.Purge(ctx, id)
}
func (r *RegisteredExecutor) PurgeReceipt(ctx context.Context, id executor.ExecutionIdentity, digest string) (node.NodePurgeReceipt, error) {
	remote, e := r.IsRemote(ctx, id)
	if e != nil {
		return node.NodePurgeReceipt{}, e
	}
	if !remote {
		return node.NodePurgeReceipt{}, config.Invalid()
	}
	return r.Remote.PurgeReceipt(ctx, id, digest)
}
func (r *RegisteredExecutor) ProxyAlive(ctx context.Context, id executor.ExecutionIdentity) (bool, error) {
	remote, e := r.IsRemote(ctx, id)
	if e != nil {
		return false, e
	}
	if !remote {
		return false, config.Invalid()
	}
	return r.Remote.ProxyAlive(ctx, id)
}
func (r *RegisteredExecutor) Binding(ctx context.Context, id executor.ExecutionIdentity, space, principal string) (map[string]any, error) {
	remote, e := r.IsRemote(ctx, id)
	if e != nil {
		return nil, e
	}
	if !remote {
		return nil, config.Invalid()
	}
	return r.Remote.Binding(ctx, id, space, principal)
}
func (r *RegisteredExecutor) ReadState(ctx context.Context, id executor.ExecutionIdentity, path string, maxBytes int64) ([]byte, error) {
	_, remote, e := r.selectExecutor(ctx, id, "")
	if e != nil {
		return nil, e
	}
	if remote {
		return r.Remote.ReadState(ctx, id, path, maxBytes)
	}
	root, e := r.Local.ReconciliationRoot(ctx, id)
	if e != nil {
		return nil, e
	}
	c, e := artifacts.NewCollector(root, artifacts.CollectorOptions{MaxFileBytes: maxBytes, MaxTotalBytes: maxBytes})
	if e != nil {
		return nil, e
	}
	defer c.Close()
	b, e := c.Read(path, maxBytes)
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	return b, e
}
func (r *RegisteredExecutor) ReadLogs(ctx context.Context, id executor.ExecutionIdentity, offset, maxBytes int64) (map[string]any, error) {
	_, remote, e := r.selectExecutor(ctx, id, "")
	if e != nil {
		return nil, e
	}
	if remote {
		return r.Remote.ReadLogs(ctx, id, offset, maxBytes)
	}
	return r.Local.ReadLogs(ctx, id, offset, maxBytes)
}
func (r *RegisteredExecutor) ReadArtifact(ctx context.Context, id executor.ExecutionIdentity, path string, maxBytes int64) ([]byte, error) {
	_, remote, e := r.selectExecutor(ctx, id, "")
	if e != nil {
		return nil, e
	}
	if remote {
		return r.Remote.ReadArtifact(ctx, id, path, maxBytes)
	}
	return r.Local.ReadArtifact(ctx, id, path, maxBytes)
}
func (r *RegisteredExecutor) WatchdogOnce(ctx context.Context) ([]executor.ExecutionIdentity, error) {
	if r.Local == nil {
		return []executor.ExecutionIdentity{}, nil
	}
	return r.Local.WatchdogOnce(ctx)
}

func QualifyRegisteredPool(ctx context.Context, services *Services, value map[string]any) (map[string]int64, error) {
	if services.Settings.Workload == nil || services.Settings.Workload.PrivateKey == "" {
		return nil, config.Invalid()
	}
	if e := EnsureBroker(services); e != nil {
		return nil, e
	}
	cfg, e := registeredNodeConfig(services.Settings)
	if e != nil {
		return nil, e
	}
	nodeID, poolID := nodeString(value["node_id"]), nodeString(value["id"])
	endpoint, ok := cfg.Endpoints[nodeID]
	registration, approved := cfg.Approvals[nodeID]
	if !ok || !approved || registration.PoolID != poolID {
		return nil, config.Invalid()
	}
	token, e := services.Broker.IssuePlatformNode(exchange.PlatformNodeRequest{NodeID: nodeID, PoolID: poolID, RegistrationID: registration.RegistrationID, CertificateThumbprint: cfg.ManagerThumbprint, TTLSeconds: 300})
	if e != nil {
		return nil, e
	}
	client, e := node.NewPlatformClient(endpoint)
	if e != nil {
		return nil, e
	}
	defer client.HTTP.CloseIdleConnections()
	report, e := client.Qualify(ctx, poolID, registration.RegistrationID, token)
	if e != nil {
		return nil, e
	}
	raw := nodeObject(report["capacity"])
	if len(raw) != 3 {
		return nil, config.Invalid()
	}
	capacity := map[string]int64{}
	for _, key := range []string{"cpu_millicores", "memory_bytes", "disk_bytes"} {
		n, e := config.Int(raw[key], 1, 1<<50)
		if e != nil {
			return nil, e
		}
		capacity[key] = n
	}
	return capacity, nil
}

func localNodeCatalog(document map[string]any) (*source.Catalog, error) {
	if e := config.Keys(document, []string{"sources", "runtime_images"}, []string{"allowed_source_hosts", "datasets", "secret_refs"}); e != nil {
		return nil, e
	}
	values, ok := document["sources"].([]any)
	if !ok || len(values) < 1 || len(values) > 100 {
		return nil, config.Invalid()
	}
	var approvals []source.Approval
	for _, raw := range values {
		m, ok := raw.(map[string]any)
		if !ok {
			return nil, config.Invalid()
		}
		if e := config.Keys(m, []string{"source_id", "projects", "commits"}, []string{"url", "mirror_path", "max_bytes", "max_files", "max_git_bytes", "max_git_files"}); e != nil {
			return nil, e
		}
		id, e := config.GetString(m, "source_id", "")
		if e != nil {
			return nil, e
		}
		projects, e := nodeStrings(m["projects"])
		if e != nil {
			return nil, e
		}
		commits, e := nodeStrings(m["commits"])
		if e != nil {
			return nil, e
		}
		url := ""
		mirror := ""
		if v := m["url"]; v != nil {
			var ok bool
			url, ok = v.(string)
			if !ok {
				return nil, config.Invalid()
			}
		}
		if v := m["mirror_path"]; v != nil {
			var ok bool
			mirror, ok = v.(string)
			if !ok {
				return nil, config.Invalid()
			}
		}
		a := source.Approval{SourceID: id, Projects: projects, Commits: commits, URL: url, MirrorPath: mirror}.Defaults()
		for key, target := range map[string]*int64{"max_bytes": &a.MaxBytes, "max_files": &a.MaxFiles, "max_git_bytes": &a.MaxGitBytes, "max_git_files": &a.MaxGitFiles} {
			if value, ok := m[key]; ok {
				n, e := config.Int(value, 1, 1<<50)
				if e != nil {
					return nil, e
				}
				*target = n
			}
		}
		if e = a.Validate(); e != nil {
			return nil, e
		}
		approvals = append(approvals, a)
	}
	hosts := []string{}
	var e error
	if value, ok := document["allowed_source_hosts"]; ok {
		hosts, e = nodeStrings(value)
		if e != nil {
			return nil, e
		}
	}
	registry, e := source.NewRegistry(approvals, hosts)
	if e != nil {
		return nil, e
	}
	rawImages, ok := document["runtime_images"].(map[string]any)
	if !ok || len(rawImages) == 0 {
		return nil, config.Invalid()
	}
	images := map[string]string{}
	for key, value := range rawImages {
		image, ok := value.(string)
		if !ok || domain.ValidateIdentifier(key) != nil {
			return nil, config.Invalid()
		}
		images[key] = image
	}
	datasets := map[string][]string{}
	if value, ok := document["datasets"]; ok {
		m, ok := value.(map[string]any)
		if !ok {
			return nil, config.Invalid()
		}
		for key, v := range m {
			if domain.ValidateIdentifier(key) != nil {
				return nil, config.Invalid()
			}
			ids, e := nodeStrings(v)
			if e != nil {
				return nil, e
			}
			for _, id := range ids {
				if domain.ValidateIdentifier(id) != nil {
					return nil, config.Invalid()
				}
			}
			datasets[key] = ids
		}
	}
	refs := []string{}
	if value, ok := document["secret_refs"]; ok {
		refs, e = nodeStrings(value)
		if e != nil {
			return nil, e
		}
		for _, ref := range refs {
			if domain.ValidateIdentifier(ref) != nil {
				return nil, config.Invalid()
			}
		}
	}
	return source.NewCatalog(registry, images, datasets, refs)
}
func localNodeSecrets(value any) (map[string]secrets.Approval, error) {
	if value == nil {
		return map[string]secrets.Approval{}, nil
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, config.Invalid()
	}
	out := map[string]secrets.Approval{}
	for id, raw := range m {
		entry, ok := raw.(map[string]any)
		if !ok || domain.ValidateIdentifier(id) != nil {
			return nil, config.Invalid()
		}
		if e := config.Keys(entry, []string{"project_id", "path", "roles", "option_names"}, []string{"purpose", "component_ids"}); e != nil {
			return nil, e
		}
		project, e := config.GetString(entry, "project_id", "")
		if e != nil {
			return nil, e
		}
		path, e := config.GetString(entry, "path", "")
		if e != nil {
			return nil, e
		}
		purpose, e := config.GetString(entry, "purpose", "plugin_option")
		if e != nil {
			return nil, e
		}
		roles, e := nodeStrings(entry["roles"])
		if e != nil {
			return nil, e
		}
		options, e := nodeStrings(entry["option_names"])
		if e != nil {
			return nil, e
		}
		components := []string{}
		if value, ok := entry["component_ids"]; ok {
			components, e = nodeStrings(value)
			if e != nil {
				return nil, e
			}
		}
		out[id] = secrets.Approval{ID: id, ProjectID: project, Path: path, Purpose: purpose, Roles: roles, OptionNames: options, ComponentIDs: components}
	}
	return out, nil
}
func localNodeCapacity(value any) (executor.ResourceLimits, error) {
	m, ok := value.(map[string]any)
	if !ok {
		return executor.ResourceLimits{}, config.Invalid()
	}
	if e := config.Keys(m, []string{"cpu_millicores", "memory_bytes", "disk_bytes"}, []string{"pids", "io_bps"}); e != nil {
		return executor.ResourceLimits{}, e
	}
	cpu, e := config.Int(m["cpu_millicores"], 1, 1<<50)
	if e != nil {
		return executor.ResourceLimits{}, e
	}
	memory, e := config.Int(m["memory_bytes"], 1, 1<<50)
	if e != nil {
		return executor.ResourceLimits{}, e
	}
	disk, e := config.Int(m["disk_bytes"], 32<<20, 1<<50)
	if e != nil {
		return executor.ResourceLimits{}, e
	}
	pids, e := config.GetInt(m, "pids", 128, 1, 65536)
	if e != nil {
		return executor.ResourceLimits{}, e
	}
	ioLimit, e := config.GetInt(m, "io_bps", 16<<20, 1, 1<<50)
	if e != nil {
		return executor.ResourceLimits{}, e
	}
	capacity := executor.ResourceLimits{CPUMillis: cpu, MemoryBytes: memory, DiskBytes: disk, PIDs: pids, IOBPS: ioLimit}
	return capacity, capacity.Validate()
}

type standaloneNodeServices struct {
	Settings                                                             config.Settings
	Values, AgentValues                                                  map[string]any
	NodeID, PoolID, RegistrationID, ProfilePath, Root, ManagerThumbprint string
	Broker                                                               *exchange.Broker
	Backend                                                              *executor.LinuxExecutor
	Runtime                                                              *executor.NodeAgent
	Materializer                                                         *node.Materializer
	Supervisor                                                           *transfer.Supervisor
	Credentials                                                          *node.CredentialClient
	Secrets                                                              *secrets.LocalResolver
	ProfileDocument                                                      map[string]any
	Closed                                                               bool
}

func (n *standaloneNodeServices) Close() error {
	if n.Closed {
		return nil
	}
	n.Closed = true
	var first error
	for _, close := range []func() error{
		func() error {
			if n.Supervisor != nil {
				return n.Supervisor.Close()
			}
			return nil
		},
		func() error {
			if n.Materializer != nil {
				return n.Materializer.Close()
			}
			return nil
		},
		func() error {
			if n.Credentials != nil {
				n.Credentials.Close()
			}
			return nil
		},
		func() error {
			if n.Runtime != nil {
				return n.Runtime.Close()
			}
			return nil
		},
	} {
		if e := close(); e != nil && first == nil {
			first = e
		}
	}
	return first
}
func transferIdentity(id executor.ExecutionIdentity) transfer.ExecutionIdentity {
	return transfer.ExecutionIdentity{JobID: id.JobID, AttemptID: id.AttemptID, ComponentID: id.ComponentID, Epoch: id.Epoch}
}
func executorIdentity(id transfer.ExecutionIdentity) executor.ExecutionIdentity {
	return executor.ExecutionIdentity{JobID: id.JobID, AttemptID: id.AttemptID, ComponentID: id.ComponentID, Epoch: id.Epoch}
}
func secretIdentity(id executor.ExecutionIdentity) secrets.Binding {
	return secrets.Binding{JobID: id.JobID, AttemptID: id.AttemptID, ComponentID: id.ComponentID, Epoch: id.Epoch}
}
func assignmentDeadline(a node.RemoteAssignment) (time.Time, error) {
	if a.Deadline == nil {
		return time.Now().UTC().Add(time.Duration(a.JobSpec.MaxDurationSeconds) * time.Second), nil
	}
	value := *a.Deadline
	if math.IsNaN(value) || math.IsInf(value, 0) || value <= 0 || value > 1e12 {
		return time.Time{}, domain.Err(409, "invalid_deadline")
	}
	seconds, fraction := math.Modf(value)
	return time.Unix(int64(seconds), int64(fraction*1e9)).UTC(), nil
}
func standaloneSettings(settings config.Settings, external bool) (map[string]any, map[string]any, error) {
	if settings.Workload == nil || settings.Workload.PublicKey == "" || settings.Workload.PrivateKey != "" {
		return nil, nil, config.Invalid()
	}
	for _, key := range []string{"provisioner", "gateway", "proxy", "nodes", "secrets"} {
		m, e := settings.Section(key, false)
		if e != nil {
			return nil, nil, e
		}
		if len(m) > 0 {
			return nil, nil, config.Invalid()
		}
	}
	values, e := settings.Section("node", true)
	if e != nil {
		return nil, nil, e
	}
	if !external {
		p, e := settings.Section("participants", false)
		if e != nil || len(p) > 0 {
			return nil, nil, config.Invalid()
		}
		required := []string{"node_id", "pool_id", "registration_id", "ledger_path", "capacity", "registry_file", "manager_endpoint", "manager_ca_file", "identity_certificate", "identity_key", "manager_certificate_thumbprint", "execution_ca_certificate", "exchange_endpoint", "gateway_endpoint", "service_ca_file"}
		if e = config.Keys(values, required, []string{"dataset_bindings", "secret_refs", "proxy_socket_root", "build_inputs", "service"}); e != nil {
			return nil, nil, e
		}
		return values, values, nil
	}
	if e = config.Keys(values, []string{"node_id", "pool_id", "ledger_path", "capacity", "dataset_bindings"}, []string{"identity_certificate", "identity_key", "identity_ca", "service", "secret_refs"}); e != nil {
		return nil, nil, e
	}
	if values["pool_id"] != "external" {
		return nil, nil, config.Invalid()
	}
	participants, e := settings.Section("participants", true)
	if e != nil {
		return nil, nil, e
	}
	if e = config.Keys(participants, []string{"agent"}, nil); e != nil {
		return nil, nil, e
	}
	agent, ok := participants["agent"].(map[string]any)
	if !ok {
		return nil, nil, config.Invalid()
	}
	required := []string{"manager_endpoint", "manager_ca_file", "node_certificate", "node_key", "certificate_ca_file", "managed_exchange_endpoint", "gateway_endpoint", "service_ca_file", "manager_certificate_thumbprints", "catalog"}
	if e = config.Keys(agent, required, []string{"proxy_socket_root"}); e != nil {
		return nil, nil, e
	}
	return values, agent, nil
}
func createStandaloneNode(ctx context.Context, settings config.Settings, external bool, nodeToken func(context.Context, executor.ExecutionIdentity, string) (string, error), workloadToken func(context.Context, executor.ExecutionIdentity, string) (string, error)) (_ *standaloneNodeServices, err error) {
	values, agentValues, e := standaloneSettings(settings, external)
	if e != nil {
		return nil, e
	}
	out := &standaloneNodeServices{Settings: settings, Values: values, AgentValues: agentValues}
	defer func() {
		if err != nil {
			_ = out.Close()
		}
	}()
	out.NodeID, e = cfgID(values["node_id"])
	if e != nil {
		return nil, e
	}
	out.PoolID, e = cfgID(values["pool_id"])
	if e != nil {
		return nil, e
	}
	executorValues, e := settings.Section("executor", true)
	if e != nil {
		return nil, e
	}
	if e = config.Keys(executorValues, []string{"root", "profile_path"}, nil); e != nil {
		return nil, e
	}
	root, e := config.GetString(executorValues, "root", "")
	if e != nil {
		return nil, e
	}
	root, e = resources.PrivateRoot(root)
	if e != nil {
		return nil, e
	}
	out.Root = root
	out.ProfilePath, e = config.GetString(executorValues, "profile_path", "")
	if e != nil {
		return nil, e
	}
	profileBytes, e := config.ReadFile(out.ProfilePath, 4<<20, false)
	if e != nil {
		return nil, e
	}
	out.ProfileDocument, e = config.DecodeJSON(profileBytes)
	if e != nil {
		return nil, e
	}
	ledger, e := config.GetString(values, "ledger_path", "")
	if e != nil || !filepath.IsAbs(ledger) || filepath.Clean(ledger) != ledger {
		return nil, config.Invalid()
	}
	relative, e := filepath.Rel(root, ledger)
	if e != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, config.Invalid()
	}
	capacity, e := localNodeCapacity(values["capacity"])
	if e != nil {
		return nil, e
	}
	rawDatasets := nodeObject(values["dataset_bindings"])
	if len(rawDatasets) > 10000 || external && len(rawDatasets) == 0 {
		return nil, config.Invalid()
	}
	for binding, value := range rawDatasets {
		m, ok := value.(map[string]any)
		if !ok || domain.ValidateIdentifier(binding) != nil {
			return nil, config.Invalid()
		}
		_, e := DatasetConfig(settings, binding, nodeString(m["project_id"]), nodeString(m["participant_id"]))
		if e != nil {
			return nil, e
		}
	}
	approvalRefs, e := localNodeSecrets(values["secret_refs"])
	if e != nil {
		return nil, e
	}
	secretRoot := filepath.Join(root, "private-secrets")
	proxyRoot := filepath.Join(root, "private-proxies")
	inputRoot := filepath.Join(root, "private-inputs")
	if external {
		secretRoot = filepath.Join(root, "sealed-secrets")
		proxyRoot = filepath.Join(root, "proxies")
		inputRoot = root
	}
	out.Secrets, e = secrets.NewLocalResolver(secretRoot, approvalRefs)
	if e != nil {
		return nil, e
	}
	datasetAuthorizer := func(ctx context.Context, bindingID string, id executor.ExecutionIdentity, participantID string) (executor.DatasetBinding, error) {
		if out.Materializer == nil {
			return executor.DatasetBinding{}, domain.Err(409, "assignment_unavailable")
		}
		a, e := out.Materializer.Assignment(ctx, id)
		if e != nil {
			return executor.DatasetBinding{}, e
		}
		return out.approvedDataset(settings, a, bindingID, participantID, external)
	}
	out.Backend, e = executor.NewLinuxExecutor(out.ProfilePath, root, executor.WithDatasetAuthorizer(datasetAuthorizer))
	if e != nil {
		return nil, e
	}
	out.Runtime, e = executor.NewNodeAgent(out.Backend, ledger, out.NodeID, out.PoolID, capacity)
	if e != nil {
		return nil, e
	}
	brokerServices := &Services{Settings: settings}
	if e = EnsureBroker(brokerServices); e != nil {
		return nil, e
	}
	out.Broker = brokerServices.Broker
	if out.Broker == nil {
		return nil, config.Invalid()
	}
	manager, ca, certificate, key, executionCA, exchangeEndpoint, serviceCA := "", "", "", "", "", "", ""
	if external {
		manager = nodeString(agentValues["manager_endpoint"])
		ca = nodeString(agentValues["manager_ca_file"])
		certificate = nodeString(agentValues["node_certificate"])
		key = nodeString(agentValues["node_key"])
		executionCA = nodeString(agentValues["certificate_ca_file"])
		exchangeEndpoint = nodeString(agentValues["managed_exchange_endpoint"])
		serviceCA = nodeString(agentValues["service_ca_file"])
	} else {
		manager = nodeString(values["manager_endpoint"])
		ca = nodeString(values["manager_ca_file"])
		certificate = nodeString(values["identity_certificate"])
		key = nodeString(values["identity_key"])
		executionCA = nodeString(values["execution_ca_certificate"])
		exchangeEndpoint = nodeString(values["exchange_endpoint"])
		serviceCA = nodeString(values["service_ca_file"])
		out.RegistrationID, e = cfgID(values["registration_id"])
		if e != nil {
			return nil, e
		}
		out.ManagerThumbprint = nodeString(values["manager_certificate_thumbprint"])
		if !nodeThumbprint(out.ManagerThumbprint) {
			return nil, config.Invalid()
		}
	}
	prefix := "nodes"
	if external {
		prefix = "participants"
	}
	out.Credentials, e = node.NewCredentialClient(node.NodeEndpoint{NodeID: out.NodeID, Origin: manager, CAFile: ca, ClientCertificate: certificate, ClientKey: key}, prefix)
	if e != nil {
		return nil, e
	}
	if nodeToken != nil {
		out.Credentials.TokenProvider = nodeToken
	}
	socketRoot := out.Backend.OwnedRoot
	if raw, ok := agentValues["proxy_socket_root"]; ok {
		provided, ok := raw.(string)
		if !ok || provided != socketRoot {
			return nil, config.Invalid()
		}
	}
	proxyConfig := transfer.SupervisorConfig{Root: proxyRoot, SocketRoot: socketRoot, ClientCACertificate: executionCA, ServiceCAFile: serviceCA, ExchangeEndpoint: exchangeEndpoint, GatewayEndpoint: nodeString(agentValues["gateway_endpoint"]), WorkloadIssuer: settings.Workload.Issuer, WorkloadPublicKey: string(out.Broker.PublicKeyPEM()), ExchangeAudience: settings.Workload.ExchangeAudience, GatewayAudience: settings.Workload.GatewayAudience}
	proxyConfig.CertificateProvider = func(ctx context.Context, id transfer.ExecutionIdentity, space string, csr []byte, expiry time.Time) (transfer.IssuedCertificate, error) {
		identity := executorIdentity(id)
		if out.Materializer == nil {
			return transfer.IssuedCertificate{}, domain.Err(503, "assignment_unavailable")
		}
		a, e := out.Materializer.Assignment(ctx, identity)
		if e != nil {
			return transfer.IssuedCertificate{}, e
		}
		component, ok := a.Component()
		if !ok {
			return transfer.IssuedCertificate{}, domain.Err(409, "assignment_conflict")
		}
		principal, e := exchange.StableWorkloadPrincipal(settings.Workload.Issuer, id.JobID, id.ComponentID, component.ParticipantID)
		if e != nil {
			return transfer.IssuedCertificate{}, e
		}
		receipt, e := out.Credentials.Certificate(ctx, identity, string(csr), space, principal)
		if e != nil {
			return transfer.IssuedCertificate{}, e
		}
		return transfer.IssuedCertificate{CertificatePEM: nodeString(receipt["certificate_pem"]), CertificateThumbprint: nodeString(receipt["certificate_thumbprint"])}, nil
	}
	proxyConfig.TokenProvider = func(ctx context.Context, binding transfer.ExecutionBinding, gateway bool) (string, error) {
		audience := "exchange"
		if gateway {
			audience = "gateway"
		}
		identity := executorIdentity(binding.Identity())
		if workloadToken != nil {
			return workloadToken(ctx, identity, audience)
		}
		return out.Credentials.Credentials(ctx, identity, binding.CertificateThumbprint, audience)
	}
	out.Supervisor, e = transfer.NewSupervisor(proxyConfig)
	if e != nil {
		return nil, e
	}
	var catalog *source.Catalog
	if external {
		raw, ok := agentValues["catalog"].(map[string]any)
		if !ok {
			return nil, config.Invalid()
		}
		raw = domain.CloneMap(raw)
		if e = config.Keys(raw, []string{"sources", "runtime_images"}, []string{"allowed_source_hosts"}); e != nil {
			return nil, e
		}
		datasets := map[string]any{}
		for binding, value := range rawDatasets {
			m := nodeObject(value)
			datasets[binding] = []string{nodeString(m["participant_id"])}
		}
		refs := []string{}
		for id := range approvalRefs {
			refs = append(refs, id)
		}
		raw["datasets"] = datasets
		raw["secret_refs"] = refs
		catalog, e = localNodeCatalog(raw)
		if e != nil {
			return nil, e
		}
		for binding, value := range rawDatasets {
			catalog.DatasetProjects[binding] = nodeString(nodeObject(value)["project_id"])
		}
	} else {
		registryFile := nodeString(values["registry_file"])
		document, e := config.ReadJSON(registryFile, 1<<20)
		if e != nil {
			return nil, e
		}
		st, e := os.Lstat(registryFile)
		if e != nil {
			return nil, e
		}
		raw, ok := st.Sys().(*syscall.Stat_t)
		if !ok || (raw.Uid != 0 && raw.Uid != uint32(os.Geteuid())) || st.Mode().Perm()&0022 != 0 {
			return nil, config.Invalid()
		}
		catalog, e = localNodeCatalog(document)
		if e != nil {
			return nil, e
		}
	}
	materializerConfig := node.MaterializerConfig{Root: inputRoot, NodeID: out.NodeID, PoolID: out.PoolID, WorkloadIssuer: settings.Workload.Issuer, Catalog: catalog, RequireSourceLimits: true}
	materializerConfig.ProxyEndpoint = func(ctx context.Context, id executor.ExecutionIdentity) (string, error) {
		return out.Supervisor.Endpoint(transferIdentity(id))
	}
	materializerConfig.AuxiliaryReserver = out.Runtime.ChargeAuxiliaryBytes
	if !external {
		materializerConfig.SharedAuxiliaryReserver = out.Runtime.ChargeSharedAuxiliaryBytes
	}
	materializerConfig.DatasetBindings = func(ctx context.Context, a node.RemoteAssignment) (map[string]any, error) {
		component, ok := a.Component()
		if !ok {
			return nil, domain.Err(409, "assignment_conflict")
		}
		if component.ParticipantID == nil {
			return map[string]any{}, nil
		}
		for _, p := range a.JobSpec.Participants {
			if p.ParticipantID == *component.ParticipantID {
				approved, e := out.approvedDataset(settings, a, p.DatasetBinding, p.ParticipantID, external)
				if e != nil {
					return nil, e
				}
				document := map[string]any{"kind": "synthetic"}
				if !approved.Synthetic {
					document = map[string]any{"kind": "npz", "path": "/job/data/data.npz"}
				}
				return map[string]any{p.DatasetBinding: document}, nil
			}
		}
		return nil, domain.Err(409, "dataset_not_approved")
	}
	materializerConfig.SecretPlanner = func(ctx context.Context, a node.RemoteAssignment) (string, error) {
		c, ok := a.Component()
		if !ok {
			return "", domain.Err(409, "assignment_conflict")
		}
		return out.Secrets.PlannedAssignment(ctx, secretIdentity(a.Identity), a.JobSpec, c)
	}
	materializerConfig.SecretMaterializer = func(ctx context.Context, a node.RemoteAssignment, document map[string]any, path string) error {
		c, ok := a.Component()
		if !ok {
			return domain.Err(409, "assignment_conflict")
		}
		return out.Secrets.MaterializeAssignment(ctx, secretIdentity(a.Identity), a.JobSpec, c, document, path)
	}
	materializerConfig.ValidateRuntime = func(document map[string]any, role string) error {
		if role == "build" {
			raw, e := domain.CanonicalJSON(document)
			if e != nil {
				return e
			}
			_, e = buildworker.DecodeConfig(raw)
			return e
		}
		return provision.ValidateRuntimeConfig(document)
	}
	materializerConfig.BuildPreparer = func(ctx context.Context, a node.RemoteAssignment, document map[string]any) error {
		approval := nodeObject(nodeObject(values["build_inputs"])[a.Identity.ComponentID])
		if len(approval) == 0 || config.Keys(approval, []string{"approved_dependencies"}, []string{"project_subdir"}) != nil {
			return domain.Err(409, "build_not_approved")
		}
		subdir, e := config.GetString(approval, "project_subdir", ".")
		if e != nil {
			return e
		}
		if !nodeSame(document["approved_dependencies"], approval["approved_dependencies"]) || document["project_subdir"] != subdir || document["source_dir"] != "/job/source" || document["state_dir"] != "/job/state" {
			return domain.Err(409, "build_not_approved")
		}
		return nil
	}
	materializerConfig.ExecutionBindings = func(ctx context.Context, a node.RemoteAssignment, space, principal string) (map[string]any, error) {
		component, ok := a.Component()
		if !ok {
			return nil, domain.Err(409, "assignment_conflict")
		}
		expected, e := exchange.StableWorkloadPrincipal(settings.Workload.Issuer, a.Identity.JobID, a.Identity.ComponentID, component.ParticipantID)
		if e != nil || principal != expected {
			return nil, domain.Err(403, "foreign_execution_binding")
		}
		observation, e := out.Runtime.Inspect(ctx, a.Identity)
		if e != nil {
			return nil, e
		}
		if !observation.TerminationConfirmed && (observation.State == "RUNNING" || observation.State == "STARTING" || observation.State == "UNKNOWN" || observation.State == "QUARANTINED") {
			alive, e := out.Supervisor.Alive(ctx, transferIdentity(a.Identity))
			if e != nil {
				return nil, e
			}
			if !alive {
				return nil, domain.Err(409, "proxy_restart_required")
			}
		}
		deadline, e := assignmentDeadline(a)
		if e != nil {
			return nil, e
		}
		binding, e := out.Supervisor.Ensure(ctx, transferIdentity(a.Identity), space, deadline)
		if e != nil {
			return nil, e
		}
		return map[string]any{"certificate_thumbprint": binding.CertificateThumbprint, "proxy_endpoint": binding.ProxyEndpoint}, nil
	}
	out.Materializer, e = node.NewMaterializer(materializerConfig)
	if e != nil {
		return nil, e
	}
	return out, nil
}
func (n *standaloneNodeServices) approvedDataset(settings config.Settings, a node.RemoteAssignment, bindingID, participantID string, external bool) (executor.DatasetBinding, error) {
	if a.NodeID != n.NodeID || a.PoolID != n.PoolID || a.Identity.Validate() != nil {
		return executor.DatasetBinding{}, domain.Err(409, "dataset_not_approved")
	}
	component, ok := a.Component()
	if !ok || component.Role != "participant" || component.ParticipantID == nil || *component.ParticipantID != participantID {
		return executor.DatasetBinding{}, domain.Err(409, "dataset_not_approved")
	}
	match := false
	for _, p := range a.JobSpec.Participants {
		if p.ParticipantID == participantID && p.DatasetBinding == bindingID && ((external && p.Mode == "external" && a.ExternalParticipantID != nil && *a.ExternalParticipantID == participantID) || (!external && p.Mode == "managed" && p.ComponentID != nil && *p.ComponentID == a.Identity.ComponentID)) {
			match = true
		}
	}
	if !match {
		return executor.DatasetBinding{}, domain.Err(409, "dataset_not_approved")
	}
	document, e := DatasetConfig(settings, bindingID, a.JobSpec.ProjectID, participantID)
	if e != nil {
		return executor.DatasetBinding{}, e
	}
	out := executor.DatasetBinding{ParticipantID: participantID, JobIDs: []string{a.Identity.JobID}}
	if document["kind"] == "synthetic" {
		out.Synthetic = true
		return out, nil
	}
	path := nodeString(document["host_path"])
	if document["kind"] != "npz" || safeDataPath(path) != nil {
		return out, domain.Err(409, "unsafe_dataset")
	}
	out.Path = path
	return out, nil
}
func (n *standaloneNodeServices) terminationConfirmed(ctx context.Context, id executor.ExecutionIdentity) (bool, error) {
	observation, e := n.Runtime.Inspect(ctx, id)
	if e == nil {
		return observation.TerminationConfirmed, nil
	}
	if executor.ErrorCode(e) == "stale_epoch" {
		return n.Runtime.ComponentPurgeAllowed(ctx, id)
	}
	return false, e
}
func (n *standaloneNodeServices) stopPrivate(ctx context.Context, id executor.ExecutionIdentity) (bool, error) {
	confirmed, e := n.terminationConfirmed(ctx, id)
	if e != nil {
		return false, e
	}
	if !confirmed {
		return false, domain.Err(409, "runtime_active")
	}
	return n.Supervisor.Stop(ctx, transferIdentity(id), true)
}
func (n *standaloneNodeServices) purgePrivate(ctx context.Context, id executor.ExecutionIdentity) (bool, error) {
	stopped, e := n.stopPrivate(ctx, id)
	if e != nil || !stopped {
		return false, e
	}
	purged, e := n.Supervisor.Purge(ctx, transferIdentity(id), true)
	if e != nil || !purged {
		return false, e
	}
	return n.Secrets.Cleanup(ctx, secretIdentity(id), true)
}
func normalizedNodeBoundary(raw map[string]any, defaultPort int) (map[string]any, error) {
	if raw == nil {
		return nil, config.Invalid()
	}
	legacy := raw["certificate"] != nil || raw["key"] != nil || raw["client_ca"] != nil
	out := domain.CloneMap(raw)
	if legacy {
		if e := config.Keys(raw, []string{"certificate", "key", "client_ca"}, []string{"host", "port"}); e != nil {
			return nil, e
		}
		out = map[string]any{"tls_certificate": raw["certificate"], "tls_key": raw["key"], "client_ca_file": raw["client_ca"]}
		for _, k := range []string{"host", "port"} {
			if v, ok := raw[k]; ok {
				out[k] = v
			}
		}
	} else {
		if e := config.Keys(raw, []string{"tls_certificate", "tls_key", "client_ca_file"}, []string{"host", "port", "graceful_shutdown_timeout_seconds"}); e != nil {
			return nil, e
		}
	}
	if _, ok := out["port"]; !ok {
		out["port"] = int64(defaultPort)
	}
	return out, nil
}
func RunManagedNode(ctx context.Context, settings config.Settings, args Arguments) error {
	env, e := createStandaloneNode(ctx, settings, false, nil, nil)
	if e != nil {
		return e
	}
	defer env.Close()
	handler, e := node.NewHandler(node.ServerConfig{
		NodeID: env.NodeID, PoolID: env.PoolID, RegistrationID: env.RegistrationID, ManagerCertificateThumbprint: env.ManagerThumbprint, Agent: env.Runtime, Materializer: env.Materializer,
		Authenticate: func(ctx context.Context, authorization, peer, scope string) (node.Principal, error) {
			if peer != env.ManagerThumbprint {
				return node.Principal{}, domain.Err(403, "node_registration_required")
			}
			p, e := env.Broker.AuthenticateNode(ctx, authorization, peer, env.Credentials.Validate)
			if e != nil {
				return p, e
			}
			if !p.HasScope(scope) {
				return p, domain.Err(403, "node_scope_required")
			}
			return p, nil
		},
		AuthenticatePlatform: func(ctx context.Context, authorization, peer string) (exchange.PlatformNodePrincipal, error) {
			if peer != env.ManagerThumbprint {
				return exchange.PlatformNodePrincipal{}, domain.Err(403, "node_registration_required")
			}
			return env.Broker.AuthenticatePlatformNode(ctx, authorization, peer, func(ctx context.Context, p exchange.PlatformNodePrincipal) (bool, error) {
				return p.NodeID == env.NodeID && p.PoolID == env.PoolID && p.RegistrationID == env.RegistrationID && p.CertificateThumbprint == env.ManagerThumbprint && len(p.Scopes) == 1 && p.Scopes[0] == "qualify", nil
			})
		},
		Qualify: func(ctx context.Context) (node.Qualification, error) {
			if e := env.Backend.QualifyHealth(ctx); e != nil {
				return node.Qualification{}, e
			}
			current, e := config.ReadJSON(env.ProfilePath, 4<<20)
			if e != nil {
				return node.Qualification{}, e
			}
			if !nodeSame(current, env.ProfileDocument) {
				return node.Qualification{}, domain.Err(409, "unqualified_profile")
			}
			return node.Qualification{Profile: current, Capacity: env.Runtime.Capacity}, nil
		},
		StopPrivate: env.stopPrivate, PurgePrivate: env.purgePrivate, ProxyAlive: func(ctx context.Context, id executor.ExecutionIdentity) (bool, error) {
			return env.Supervisor.Alive(ctx, transferIdentity(id))
		},
	})
	if e != nil {
		return e
	}
	boundary, e := settings.Section("service", false)
	if e != nil {
		return e
	}
	if len(boundary) == 0 {
		boundary = nodeObject(env.Values["service"])
	}
	boundary, e = normalizedNodeBoundary(boundary, 9444)
	if e != nil {
		return e
	}
	return RunMTLS(ctx, settings, args, handler, boundary)
}

// RemoteAuxiliaryStorageTx prepays both shared source/build staging and each
// attempt's private credentials before a registered node can receive an assignment.
// All approval and pool reads use the caller's admission transaction.
func RemoteAuxiliaryStorageTx(ctx context.Context, services *Services, tx *store.Tx, job map[string]any) ([]map[string]any, error) {
	endpoints := nodeObject(nodeObject(services.Settings.Extra["nodes"])["endpoints"])
	if len(endpoints) == 0 {
		return []map[string]any{}, nil
	}
	encoded, err := domain.CanonicalJSON(job["spec_json"])
	if err != nil {
		return nil, err
	}
	spec, err := domain.DecodeJobSpec(encoded)
	if err != nil {
		return nil, err
	}
	digest, err := spec.Digest()
	if err != nil {
		return nil, err
	}
	if digest != nodeString(job["spec_hash"]) || nodeString(job["project_id"]) != spec.ProjectID || domain.ValidateIdentifier(nodeString(job["id"])) != nil {
		return nil, config.Invalid()
	}
	row, err := tx.One(ctx, "SELECT * FROM jm_approved_sources WHERE id=?", spec.SourceID)
	if err != nil {
		return nil, err
	}
	if row == nil || row["enabled"] != true || row["status"] != "approved" || (nodeString(row["project_id"]) != "" && row["project_id"] != spec.ProjectID) {
		return nil, domain.Err(409, "source_not_approved")
	}
	details := nodeObject(row["details_json"])
	commits, err := nodeStrings(row["allowed_commits"])
	if err != nil {
		return nil, err
	}
	hosts, err := nodeStrings(row["allowed_hosts"])
	if err != nil {
		return nil, err
	}
	approval := source.Approval{SourceID: spec.SourceID, Projects: []string{spec.ProjectID}, URL: nodeString(row["url"]), MirrorPath: nodeString(details["mirror_path"]), Commits: commits}
	if approval.MirrorPath != "" {
		approval.URL = ""
	}
	for _, limit := range []struct {
		name   string
		target *int64
	}{{"max_bytes", &approval.MaxBytes}, {"max_files", &approval.MaxFiles}, {"max_git_bytes", &approval.MaxGitBytes}, {"max_git_files", &approval.MaxGitFiles}} {
		if value, exists := details[limit.name]; exists {
			n, ok := nodeInteger(value)
			if !ok || n < 1 {
				return nil, config.Invalid()
			}
			*limit.target = n
		}
	}
	registry, err := source.NewRegistry([]source.Approval{approval}, hosts)
	if err != nil {
		return nil, err
	}
	approval, err = registry.Authorize(spec.ProjectID, spec.SourceID, spec.SourceCommit)
	if err != nil {
		return nil, err
	}
	limits := map[string]int64{"max_bytes": approval.MaxBytes, "max_files": approval.MaxFiles, "max_git_bytes": approval.MaxGitBytes, "max_git_files": approval.MaxGitFiles}
	builders := int64(0)
	for _, component := range spec.Components {
		if component.Role == "build" {
			builders++
		}
	}
	attempt, ok := nodeInteger(job["current_attempt"])
	if !ok || attempt < 0 {
		return nil, config.Invalid()
	}
	if attempt < 1 {
		attempt = 1
	}
	entries := []map[string]any{}
	for _, component := range spec.Components {
		pool, err := tx.One(ctx, "SELECT * FROM jm_pools WHERE id=?", component.Resources.PoolID)
		if err != nil {
			return nil, err
		}
		if pool == nil {
			return nil, config.Invalid()
		}
		nodeID := nodeString(pool["node_id"])
		value, exists := endpoints[nodeID]
		if !exists {
			continue
		}
		registration, ok := value.(map[string]any)
		if !ok {
			return nil, config.Invalid()
		}
		enabled, err := config.GetBool(registration, "enabled", true)
		if err != nil {
			return nil, err
		}
		if !enabled || nodeString(registration["pool_id"]) != component.Resources.PoolID || domain.ValidateIdentifier(nodeID) != nil {
			return nil, config.Invalid()
		}
		buildBytes := int64(0)
		if component.Role != "build" && builders > 0 {
			if builders > math.MaxInt64/8192-4 {
				return nil, config.Invalid()
			}
			buildBytes = min(int64(256<<20), component.Resources.DiskBytes) + 8192*(builders+4)
		}
		shared := int64(0)
		for _, value := range []int64{approval.MaxBytes, source.MetadataPeakBytes(approval), source.GitPeakBytes(approval), buildBytes} {
			if value < 0 || shared > math.MaxInt64-value {
				return nil, config.Invalid()
			}
			shared += value
		}
		prefix := "hf2l-node-inputs://" + nodeID + "/" + nodeString(job["id"]) + "/" + component.ComponentID
		for _, scope := range []string{"shared", "attempt_private"} {
			maximum := shared
			external := prefix + "/shared"
			resourceDetails := map[string]any{"node_id": nodeID, "pool_id": component.Resources.PoolID, "spec_digest": digest, "scope": scope}
			if scope == "shared" {
				resourceDetails["source_limits"] = limits
			} else {
				maximum = 4<<20 + 256<<10
				external = prefix + "/attempt/" + strconv.FormatInt(attempt, 10)
				resourceDetails["attempt_number"] = attempt
			}
			resourceDetails["reservation_max_bytes"] = maximum
			entries = append(entries, map[string]any{"kind": "remote_auxiliary", "external_id": external, "component_id": component.ComponentID, "pool_id": component.Resources.PoolID, "max_bytes": maximum, "details": resourceDetails})
		}
	}
	return entries, nil
}

// RemoteAuxiliaryCleanup requires an authenticated physical purge receipt for
// every historical allocation owning the resource, including released attempts.
func RemoteAuxiliaryCleanup(ctx context.Context, services *Services, job map[string]any, resources []map[string]any) (map[string][]map[string]any, error) {
	backend, ok := services.Node.(interface {
		IsRemote(context.Context, executor.ExecutionIdentity) (bool, error)
		PurgeReceipt(context.Context, executor.ExecutionIdentity, string) (node.NodePurgeReceipt, error)
	})
	if !ok {
		return nil, config.Invalid()
	}
	encoded, err := domain.CanonicalJSON(job["spec_json"])
	if err != nil {
		return nil, err
	}
	spec, err := domain.DecodeJobSpec(encoded)
	if err != nil {
		return nil, err
	}
	digest, err := spec.Digest()
	if err != nil {
		return nil, err
	}
	jobID := nodeString(job["id"])
	if digest != nodeString(job["spec_hash"]) || domain.ValidateIdentifier(jobID) != nil {
		return nil, config.Invalid()
	}
	proofs := map[string][]map[string]any{}
	for _, resource := range resources {
		details := nodeObject(resource["details"])
		if len(details) == 0 {
			details = nodeObject(resource["details_json"])
		}
		resourceID := nodeString(resource["id"])
		componentID := nodeString(resource["component_id"])
		nodeID := nodeString(details["node_id"])
		poolID := nodeString(details["pool_id"])
		if domain.ValidateIdentifier(resourceID) != nil || domain.ValidateIdentifier(nodeID) != nil || details["spec_digest"] != digest {
			return nil, config.Invalid()
		}
		matched := false
		for _, component := range spec.Components {
			if component.ComponentID == componentID && component.Resources.PoolID == poolID {
				matched = true
			}
		}
		if !matched {
			return nil, config.Invalid()
		}
		var allocations []map[string]any
		err = services.DB.WithTx(ctx, false, func(tx *store.Tx) error {
			var e error
			allocations, e = tx.All(ctx, "SELECT * FROM jm_allocations WHERE job_id=? AND component_id=? AND pool_id=? ORDER BY id", jobID, componentID, poolID)
			return e
		})
		if err != nil {
			return nil, err
		}
		receipts := []map[string]any{}
		for _, allocation := range allocations {
			if nodeObject(allocation["details_json"])["node_id"] != nodeID {
				continue
			}
			epoch, valid := nodeInteger(allocation["epoch"])
			if !valid {
				return nil, config.Invalid()
			}
			identity := executor.ExecutionIdentity{JobID: jobID, AttemptID: nodeString(allocation["attempt_id"]), ComponentID: componentID, Epoch: epoch}
			remote, e := backend.IsRemote(ctx, identity)
			if e != nil {
				return nil, e
			}
			if !remote {
				return nil, config.Invalid()
			}
			receipt, e := backend.PurgeReceipt(ctx, identity, digest)
			if e != nil {
				return nil, e
			}
			if e = receipt.Validate(); e != nil {
				return nil, e
			}
			if receipt.Identity() != identity || receipt.NodeID != nodeID || receipt.PoolID != poolID || receipt.SpecDigest != digest {
				return nil, domain.Err(409, "invalid_purge_receipt")
			}
			data, e := domain.CanonicalJSON(receipt)
			if e != nil {
				return nil, e
			}
			value, e := domain.DecodeJSON(data)
			if e != nil {
				return nil, e
			}
			receipts = append(receipts, nodeObject(value))
		}
		if len(receipts) == 0 {
			return nil, domain.Err(409, "missing_purge_receipt")
		}
		if _, duplicate := proofs[resourceID]; duplicate {
			return nil, config.Invalid()
		}
		proofs[resourceID] = receipts
	}
	return proofs, nil
}
