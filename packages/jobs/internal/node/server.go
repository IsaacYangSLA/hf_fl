package node

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/exchange"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"golang.org/x/sys/unix"
)

type LocalAgent interface {
	executor.FullBackend
	RenewLease(context.Context, executor.ExecutionIdentity, float64) error
	AssignmentResources(context.Context, executor.ExecutionIdentity, bool) (map[string]int64, error)
	ReadLogs(context.Context, executor.ExecutionIdentity, int64, int64) (map[string]any, error)
	ReadArtifact(context.Context, executor.ExecutionIdentity, string, int64) ([]byte, error)
	ReconciliationRoot(context.Context, executor.ExecutionIdentity) (string, error)
	RetainedManifest(context.Context, executor.ExecutionIdentity) ([]executor.CollectedArtifact, error)
	ChargeAuxiliaryBytes(context.Context, executor.ExecutionIdentity, int64) (bool, error)
	ComponentPurgeAllowed(context.Context, executor.ExecutionIdentity) (bool, error)
	PurgeWithAuxiliary(context.Context, executor.ExecutionIdentity, bool) (bool, error)
	WithComponentGuardContext(context.Context, executor.ExecutionIdentity, bool, func(context.Context) error) error
}
type Qualification struct {
	Profile  map[string]any
	Capacity executor.ResourceLimits
}
type ServerConfig struct {
	NodeID, PoolID, RegistrationID, ManagerCertificateThumbprint string
	Agent                                                        LocalAgent
	Materializer                                                 *Materializer
	Authenticate                                                 func(context.Context, string, string, string) (Principal, error)
	AuthenticatePlatform                                         func(context.Context, string, string) (exchange.PlatformNodePrincipal, error)
	Qualify                                                      func(context.Context) (Qualification, error)
	StopPrivate, PurgePrivate, ProxyAlive                        func(context.Context, executor.ExecutionIdentity) (bool, error)
}
type Server struct{ Config ServerConfig }

func NewHandler(cfg ServerConfig) (http.Handler, error) {
	if cfg.Agent == nil || cfg.Materializer == nil || cfg.Authenticate == nil || domain.ValidateIdentifier(cfg.NodeID) != nil || domain.ValidateIdentifier(cfg.PoolID) != nil || cfg.Materializer.Config.NodeID != cfg.NodeID || cfg.Materializer.Config.PoolID != cfg.PoolID {
		return nil, domain.Err(422, "invalid_node_configuration")
	}
	if cfg.RegistrationID != "" && domain.ValidateIdentifier(cfg.RegistrationID) != nil {
		return nil, domain.Err(422, "invalid_node_registration")
	}
	if cfg.ManagerCertificateThumbprint != "" && validateThumbprint(cfg.ManagerCertificateThumbprint) != nil {
		return nil, domain.Err(422, "invalid_manager_certificate")
	}
	if cfg.Materializer.Config.ExecutionBindings != nil && (cfg.StopPrivate == nil || cfg.PurgePrivate == nil) {
		return nil, domain.Err(422, "private_node_lifecycle_required")
	}
	if cfg.Materializer.Config.SecretMaterializer != nil && cfg.PurgePrivate == nil {
		return nil, domain.Err(422, "private_node_lifecycle_required")
	}
	return &Server{Config: cfg}, nil
}
func VerifiedPeer(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		return "", domain.Err(401, "verified_node_certificate_required")
	}
	peer := r.TLS.PeerCertificates[0]
	valid := false
	for _, chain := range r.TLS.VerifiedChains {
		if len(chain) > 0 && subtle.ConstantTimeCompare(chain[0].Raw, peer.Raw) == 1 {
			valid = true
		}
	}
	if !valid {
		return "", domain.Err(401, "verified_node_certificate_required")
	}
	return Thumbprint(peer.Raw), nil
}
func nodeError(w http.ResponseWriter, err error) {
	status := 503
	code := "execution_unknown"
	var de *domain.Error
	if errors.As(err, &de) {
		status = de.Status
		code = de.Code
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code}})
}
func nodeJSON(w http.ResponseWriter, result any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(result)
}
func readBody(w http.ResponseWriter, r *http.Request, allowed []string) (map[string]any, error) {
	data, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
	if e != nil {
		var max *http.MaxBytesError
		if errors.As(e, &max) {
			return nil, domain.Err(413, "assignment_body_exceeds_bound")
		}
		return nil, domain.Err(422, "invalid_assignment")
	}
	if len(data) == 0 {
		return nil, domain.Err(422, "invalid_assignment")
	}
	var out map[string]any
	if strictDecode(data, &out) != nil || out == nil {
		return nil, domain.Err(422, "invalid_assignment")
	}
	keys := map[string]bool{}
	for _, k := range allowed {
		keys[k] = true
	}
	for k := range out {
		if !keys[k] {
			return nil, domain.Err(422, "invalid_assignment")
		}
	}
	return out, nil
}
func decodeIdentity(v any) (executor.ExecutionIdentity, error) {
	b, e := domain.CanonicalJSON(v)
	if e != nil {
		return executor.ExecutionIdentity{}, domain.Err(422, "invalid_assignment")
	}
	var id executor.ExecutionIdentity
	if strictDecode(b, &id) != nil || id.Validate() != nil {
		return id, domain.Err(422, "invalid_assignment")
	}
	return id, nil
}
func opScope(op string) string {
	if value := map[string]string{"prepare": "assignment", "binding": "assignment", "stage-build": "assignment", "proxy-alive": "inspect", "read-artifact": "collect", "read-state": "collect", "read-logs": "logs", "health": "heartbeat"}[op]; value != "" {
		return value
	}
	return op
}
func (s *Server) authenticate(ctx context.Context, r *http.Request, operation string, id executor.ExecutionIdentity, provided *RemoteAssignment) (RemoteAssignment, error) {
	peer, e := VerifiedPeer(r)
	if e != nil {
		return RemoteAssignment{}, e
	}
	scope := opScope(operation)
	p, e := s.Config.Authenticate(ctx, r.Header.Get("Authorization"), peer, scope)
	if e != nil {
		return RemoteAssignment{}, e
	}
	if p.NodeID != s.Config.NodeID || p.PoolID != s.Config.PoolID || principalIdentity(p) != id || !p.HasScope(scope) || subtle.ConstantTimeCompare([]byte(p.CertificateThumbprint), []byte(peer)) != 1 {
		return RemoteAssignment{}, domain.Err(403, "node_assignment_binding_mismatch")
	}
	var a RemoteAssignment
	if provided != nil {
		a = *provided
	} else {
		a, e = s.Config.Materializer.Assignment(ctx, id)
		if e != nil {
			safeOld := map[string]bool{"inspect": true, "stop": true, "collect": true, "release": true, "purge": true, "read-state": true, "read-artifact": true, "read-logs": true}
			if !safeOld[operation] || !errors.Is(e, os.ErrNotExist) {
				return a, e
			}
			resources, e := s.Config.Agent.AssignmentResources(ctx, id, true)
			if e != nil {
				return a, e
			}
			a = RemoteAssignment{Identity: id, NodeID: s.Config.NodeID, PoolID: s.Config.PoolID, Resources: executor.ResourceLimits{CPUMillis: resources["cpu_millicores"], MemoryBytes: resources["memory_bytes"], DiskBytes: resources["disk_bytes"]}.Defaults()}
		}
	}
	expected := map[string]any{"cpu_millicores": a.Resources.CPUMillis, "memory_bytes": a.Resources.MemoryBytes, "disk_bytes": a.Resources.DiskBytes}
	if !numericEqual(p.Resources, expected) {
		return a, domain.Err(403, "node_resource_binding_mismatch")
	}
	return a, nil
}
func (s *Server) qualify(ctx context.Context) (Qualification, error) {
	if s.Config.Qualify == nil {
		return Qualification{}, domain.Err(409, "unqualified_profile")
	}
	q, e := s.Config.Qualify(ctx)
	if e != nil {
		return q, e
	}
	if q.Profile["qualified"] != true || q.Profile["runtime"] != "runsc" || q.Profile["network"] != "none" || q.Profile["bounded_volumes"] != "loop-ext4" || q.Capacity.Defaults().Validate() != nil {
		return q, domain.Err(409, "unqualified_profile")
	}
	return q, nil
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		nodeError(w, domain.Err(405, "method_not_allowed"))
		return
	}
	const prefix = "/internal/nodes/v1/"
	if !strings.HasPrefix(r.URL.Path, prefix) || strings.Contains(r.URL.RawPath, "%") || r.URL.RawQuery != "" {
		nodeError(w, domain.Err(404, "node_operation_not_found"))
		return
	}
	op := strings.TrimPrefix(r.URL.Path, prefix)
	allowed := map[string][]string{
		"qualify": {"node_id", "pool_id", "registration_id"}, "health": {"identity", "resources"}, "reserve": {"assignment"},
		"start": {"identity"}, "inspect": {"identity"}, "stop": {"identity", "grace_seconds"}, "collect": {"identity"}, "release": {"identity"}, "renew": {"identity", "lease_seconds"}, "purge": {"identity", "spec_digest"},
		"prepare": {"identity", "runtime_config", "execution_binding"}, "binding": {"identity", "space_id", "principal_id"}, "stage-build": {"identity", "artifacts", "filename", "offset", "data_base64"}, "proxy-alive": {"identity"}, "read-artifact": {"identity", "path", "max_bytes"}, "read-state": {"identity", "path", "max_bytes"}, "read-logs": {"identity", "offset", "max_bytes"},
	}
	keys, ok := allowed[op]
	if !ok {
		nodeError(w, domain.Err(404, "node_operation_not_found"))
		return
	}
	doc, e := readBody(w, r, keys)
	if e != nil {
		nodeError(w, e)
		return
	}
	var result any
	if op == "qualify" {
		result, e = s.platform(r, doc)
	} else if op == "reserve" {
		result, e = s.reserve(r, doc)
	} else {
		var id executor.ExecutionIdentity
		id, e = decodeIdentity(doc["identity"])
		if e == nil {
			var assignment RemoteAssignment
			if op == "health" {
				result, e = s.health(r, id, doc)
			} else if assignment, e = s.authenticate(r.Context(), r, op, id, nil); e == nil {
				result, e = s.operate(r.Context(), op, id, assignment, doc)
			}
		}
	}
	if e != nil {
		nodeError(w, e)
		return
	}
	if b, ok := result.([]byte); ok {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(b)
		return
	}
	nodeJSON(w, result)
}
func (s *Server) platform(r *http.Request, doc map[string]any) (any, error) {
	peer, e := VerifiedPeer(r)
	if e != nil {
		return nil, e
	}
	if s.Config.AuthenticatePlatform == nil || s.Config.RegistrationID == "" {
		return nil, domain.Err(401, "node_registration_required")
	}
	if s.Config.ManagerCertificateThumbprint == "" || peer != s.Config.ManagerCertificateThumbprint {
		return nil, domain.Err(403, "node_registration_required")
	}
	if len(doc) != 3 || doc["node_id"] != s.Config.NodeID || doc["pool_id"] != s.Config.PoolID || doc["registration_id"] != s.Config.RegistrationID {
		return nil, domain.Err(403, "node_registration_required")
	}
	p, e := s.Config.AuthenticatePlatform(r.Context(), r.Header.Get("Authorization"), peer)
	if e != nil {
		return nil, e
	}
	if p.NodeID != s.Config.NodeID || p.PoolID != s.Config.PoolID || p.RegistrationID != s.Config.RegistrationID || p.CertificateThumbprint != peer || len(p.Scopes) != 1 || p.Scopes[0] != "qualify" {
		return nil, domain.Err(403, "node_registration_required")
	}
	q, e := s.qualify(r.Context())
	if e != nil {
		return nil, e
	}
	digest, e := domain.SpecHash(q.Profile)
	if e != nil {
		return nil, e
	}
	return map[string]any{"node_id": s.Config.NodeID, "pool_id": s.Config.PoolID, "registration_id": s.Config.RegistrationID, "healthy": true, "capacity": map[string]any{"cpu_millicores": q.Capacity.CPUMillis, "memory_bytes": q.Capacity.MemoryBytes, "disk_bytes": q.Capacity.DiskBytes}, "sandbox_profiles": []string{"runsc-cpu-v1"}, "profile_attestations": map[string]any{"runsc-cpu-v1": map[string]any{"qualified": true, "profile_sha256": digest, "runtime": "runsc", "network": "none", "bounded_volumes": "loop-ext4"}}}, nil
}
func (s *Server) health(r *http.Request, id executor.ExecutionIdentity, doc map[string]any) (any, error) {
	peer, e := VerifiedPeer(r)
	if e != nil {
		return nil, e
	}
	p, e := s.Config.Authenticate(r.Context(), r.Header.Get("Authorization"), peer, "heartbeat")
	if e != nil {
		return nil, e
	}
	var limits executor.ResourceLimits
	b, e := domain.CanonicalJSON(doc["resources"])
	if e != nil || strictDecode(b, &limits) != nil {
		return nil, domain.Err(422, "invalid_assignment")
	}
	limits = limits.Defaults()
	if limits.Validate() != nil || p.NodeID != s.Config.NodeID || p.PoolID != s.Config.PoolID || principalIdentity(p) != id || p.CertificateThumbprint != peer || !p.HasScope("heartbeat") || !numericEqual(p.Resources, map[string]any{"cpu_millicores": limits.CPUMillis, "memory_bytes": limits.MemoryBytes, "disk_bytes": limits.DiskBytes}) {
		return nil, domain.Err(403, "node_assignment_binding_mismatch")
	}
	q, e := s.qualify(r.Context())
	if e != nil {
		return nil, e
	}
	return map[string]any{"node_id": s.Config.NodeID, "pool_id": s.Config.PoolID, "healthy": true, "capacity": map[string]any{"cpu_millicores": q.Capacity.CPUMillis, "memory_bytes": q.Capacity.MemoryBytes, "disk_bytes": q.Capacity.DiskBytes}, "sandbox_profiles": []string{"runsc-cpu-v1"}}, nil
}
func (s *Server) reserve(r *http.Request, doc map[string]any) (any, error) {
	b, e := domain.CanonicalJSON(doc["assignment"])
	if e != nil {
		return nil, domain.Err(422, "invalid_assignment")
	}
	a, e := DecodeAssignment(b)
	if e != nil {
		return nil, e
	}
	if _, e = s.authenticate(r.Context(), r, "reserve", a.Identity, &a); e != nil {
		return nil, e
	}
	var receipt executor.Reservation
	e = s.Config.Agent.WithComponentGuardContext(r.Context(), a.Identity, false, func(ctx context.Context) error {
		return s.Config.Materializer.WithPending(a, func() error {
			plan, e := s.Config.Materializer.Plan(ctx, a)
			if e != nil {
				return e
			}
			receipt, e = s.Config.Agent.Reserve(ctx, plan)
			if e != nil {
				return e
			}
			if s.Config.Materializer.Config.AuxiliaryReserver != nil {
				ok, e := s.Config.Materializer.Config.AuxiliaryReserver(ctx, a.Identity, (4<<20)+(256<<10))
				if e != nil {
					return e
				}
				if !ok {
					return domain.Err(409, "resource_limit_exceeded")
				}
			}
			_, e = s.Config.Materializer.Reserve(ctx, a)
			return e
		})
	})
	return receipt, e
}
func (s *Server) guard(ctx context.Context, id executor.ExecutionIdentity, fn func(context.Context) (any, error)) (any, error) {
	var result any
	e := s.Config.Agent.WithComponentGuardContext(ctx, id, false, func(ctx context.Context) error {
		if _, e := s.Config.Agent.AssignmentResources(ctx, id, false); e != nil {
			return e
		}
		var e error
		result, e = fn(ctx)
		return e
	})
	return result, e
}
func (s *Server) operate(ctx context.Context, op string, id executor.ExecutionIdentity, a RemoteAssignment, doc map[string]any) (any, error) {
	switch op {
	case "start":
		return s.Config.Agent.Start(ctx, id)
	case "inspect":
		return s.Config.Agent.Inspect(ctx, id)
	case "collect":
		files, e := s.Config.Agent.Collect(ctx, id)
		if e != nil {
			return nil, e
		}
		out := make([]map[string]any, 0, len(files))
		for _, f := range files {
			out = append(out, map[string]any{"path": f.Path, "size_bytes": f.SizeBytes, "sha256": f.SHA256, "kind": f.Kind, "metadata": f.Metadata})
		}
		return out, nil
	case "stop":
		grace := int64(60)
		if v, ok := doc["grace_seconds"]; ok {
			grace = number(v)
		}
		if grace < 0 || grace > 60 {
			return nil, domain.Err(422, "invalid_assignment")
		}
		out, e := s.Config.Agent.Stop(ctx, id, int(grace))
		if e != nil {
			return out, e
		}
		if out.TerminationConfirmed && s.Config.StopPrivate != nil {
			ok, e := s.Config.StopPrivate(ctx, id)
			if e != nil {
				return nil, e
			}
			if !ok {
				return nil, uncertain(errors.New("private proxy stop unconfirmed"))
			}
		}
		return out, nil
	case "release":
		if s.Config.StopPrivate != nil {
			ok, e := s.Config.StopPrivate(ctx, id)
			if e != nil {
				return nil, e
			}
			if !ok {
				return nil, uncertain(errors.New("private proxy stop unconfirmed"))
			}
		}
		ok, e := s.Config.Agent.Release(ctx, id)
		return map[string]any{"confirmed": ok}, e
	case "renew":
		lease := float64(120)
		if v, ok := doc["lease_seconds"]; ok {
			lease = floatValue(v)
		}
		if lease <= 0 || lease > 300 || mathInvalid(lease) {
			return nil, domain.Err(422, "invalid_lease")
		}
		e := s.Config.Agent.RenewLease(ctx, id, lease)
		return map[string]any{"confirmed": e == nil}, e
	case "read-logs":
		offset := int64(0)
		limit := int64(65536)
		if v, ok := doc["offset"]; ok {
			offset = number(v)
		}
		if v, ok := doc["max_bytes"]; ok {
			limit = number(v)
		}
		if offset < 0 || limit < 4 || limit > 65536 {
			return nil, domain.Err(422, "invalid_assignment")
		}
		return s.Config.Agent.ReadLogs(ctx, id, offset, limit)
	case "proxy-alive":
		if _, e := s.Config.Agent.AssignmentResources(ctx, id, false); e != nil {
			return nil, e
		}
		if s.Config.ProxyAlive == nil {
			return nil, domain.Err(409, "proxy_restart_required")
		}
		alive, e := s.Config.ProxyAlive(ctx, id)
		return map[string]any{"identity": id, "alive": alive}, e
	case "binding":
		return s.guard(ctx, id, func(ctx context.Context) (any, error) {
			return s.Config.Materializer.Binding(ctx, id, valueString(doc["space_id"]), valueString(doc["principal_id"]))
		})
	case "stage-build":
		return s.guard(ctx, id, func(ctx context.Context) (any, error) {
			ok, e := s.Config.Materializer.StageBuildInput(ctx, id, valueMap(doc["artifacts"]), valueString(doc["filename"]), number(doc["offset"]), valueString(doc["data_base64"]))
			return map[string]any{"confirmed": ok}, e
		})
	case "prepare":
		return s.guard(ctx, id, func(ctx context.Context) (any, error) {
			ok, e := s.Config.Materializer.Prepare(ctx, id, valueMap(doc["runtime_config"]), valueMap(doc["execution_binding"]))
			return map[string]any{"confirmed": ok}, e
		})
	case "read-artifact", "read-state":
		limit := int64(1 << 20)
		if v, ok := doc["max_bytes"]; ok {
			limit = number(v)
		}
		if limit < 0 || limit > min(int64(1<<30), a.Resources.DiskBytes) || !safeRelative(valueString(doc["path"])) {
			return nil, domain.Err(422, "invalid_assignment")
		}
		if op == "read-artifact" {
			return s.Config.Agent.ReadArtifact(ctx, id, valueString(doc["path"]), limit)
		}
		observation, e := s.Config.Agent.Inspect(ctx, id)
		if e != nil {
			return nil, e
		}
		if !observation.TerminationConfirmed {
			return nil, domain.Err(409, "runtime_active")
		}
		root, e := s.Config.Agent.ReconciliationRoot(ctx, id)
		if e != nil {
			return nil, e
		}
		data, e := readState(root, valueString(doc["path"]), limit)
		if errors.Is(e, os.ErrNotExist) {
			return nil, domain.Err(404, "state_file_missing")
		}
		return data, e
	case "purge":
		return s.purge(ctx, id, a, valueString(doc["spec_digest"]))
	}
	return nil, domain.Err(404, "node_operation_not_found")
}
func mathInvalid(value float64) bool { return value != value || value > 1e300 || value < -1e300 }
func readState(root, path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(root) || !safeRelative(path) {
		return nil, domain.Err(409, "unsafe_output")
	}
	rootfd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	dir := os.NewFile(uintptr(rootfd), "owned state root")
	defer func() { dir.Close() }()
	for _, part := range strings.Split(strings.TrimPrefix(root, "/"), "/") {
		if part == "" || part == "." || part == ".." {
			return nil, domain.Err(409, "unsafe_output")
		}
		fd, e := unix.Openat(int(dir.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, e
		}
		dir.Close()
		dir = os.NewFile(uintptr(fd), "owned state directory")
	}
	var rootStat unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &rootStat) != nil || rootStat.Uid != uint32(os.Geteuid()) || rootStat.Mode&0022 != 0 {
		return nil, domain.Err(409, "unsafe_output")
	}
	parts := splitRelative(path)
	for _, part := range parts[:len(parts)-1] {
		fd, e := unix.Openat(int(dir.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, e
		}
		dir.Close()
		dir = os.NewFile(uintptr(fd), "owned state directory")
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 {
			return nil, domain.Err(409, "unsafe_output")
		}
	}
	fd, e := unix.Openat(int(dir.Fd()), parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "owned node state")
	defer f.Close()
	before, e := f.Stat()
	if e != nil {
		return nil, e
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || before.Size() > limit {
		return nil, domain.Err(409, "unsafe_output")
	}
	data, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(data)) > limit {
		return nil, domain.Err(409, "unsafe_output")
	}
	after, e := f.Stat()
	if e != nil {
		return nil, e
	}
	ast := after.Sys().(*syscall.Stat_t)
	if st.Dev != ast.Dev || st.Ino != ast.Ino || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || st.Ctim != ast.Ctim {
		return nil, domain.Err(409, "unsafe_output")
	}
	return data, nil
}
func (s *Server) purge(ctx context.Context, id executor.ExecutionIdentity, a RemoteAssignment, expected string) (any, error) {
	var result NodePurgeReceipt
	e := s.Config.Agent.WithComponentGuardContext(ctx, id, true, func(ctx context.Context) error {
		if cached, e := s.Config.Materializer.PurgeReceipt(id); e == nil {
			if expected != "" && cached.SpecDigest != expected {
				return domain.Err(409, "assignment_conflict")
			}
			result = cached
			return nil
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		allowed, e := s.Config.Agent.ComponentPurgeAllowed(ctx, id)
		if e != nil {
			return e
		}
		if !allowed {
			return domain.Err(409, "runtime_active")
		}
		local, e := a.JobSpec.Digest()
		if e != nil || a.JobSpec.ProjectID == "" {
			local = expected
		}
		if expected != "" && expected != local {
			return domain.Err(409, "assignment_conflict")
		}
		if !digestPattern.MatchString(local) {
			return domain.Err(409, "invalid_purge_receipt")
		}
		if s.Config.PurgePrivate != nil {
			ok, e := s.Config.PurgePrivate(ctx, id)
			if e != nil {
				return e
			}
			if !ok {
				return uncertain(errors.New("private resource deletion unconfirmed"))
			}
		} else if s.Config.Materializer.Config.ExecutionBindings != nil || s.Config.Materializer.Config.SecretMaterializer != nil {
			return domain.Err(409, "invalid_purge_receipt")
		}
		ok, e := s.Config.Materializer.Purge(ctx, id)
		if e != nil {
			return e
		}
		if !ok {
			return uncertain(errors.New("component deletion unconfirmed"))
		}
		ok, e = s.Config.Agent.PurgeWithAuxiliary(ctx, id, true)
		if e != nil {
			return e
		}
		if !ok {
			return uncertain(errors.New("retained deletion unconfirmed"))
		}
		result = NodePurgeReceipt{JobID: id.JobID, AttemptID: id.AttemptID, ComponentID: id.ComponentID, Epoch: id.Epoch, NodeID: s.Config.NodeID, PoolID: s.Config.PoolID, SpecDigest: local, OperationID: "purge-" + id.Key(), Purpose: "managed_node_purge", TerminationConfirmed: true, SourceDeleted: true, ConfigDeleted: true, BuildDeleted: true, PrivateCredentialsDeleted: true, PrivateSecretsDeleted: true, RetainedDeleted: true, AuxiliaryDeleted: true, Confirmed: true}
		return s.Config.Materializer.WritePurgeReceipt(result)
	})
	return result, e
}

var _ LocalAgent = (*executor.NodeAgent)(nil)
