package participants

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/exchange"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/node"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/resources"
	"golang.org/x/sys/unix"
)

func invalidAgent() error { return domain.Err(422, "invalid_participant_agent") }
func (a *Agent) guardFor(id executor.ExecutionIdentity) *sync.Mutex {
	a.mu.Lock()
	defer a.mu.Unlock()
	lock := a.flowGuards[id.Key()]
	if lock == nil {
		lock = &sync.Mutex{}
		a.flowGuards[id.Key()] = lock
	}
	return lock
}
func (a *Agent) withFlow(ctx context.Context, id executor.ExecutionIdentity, fn func() error) error {
	root := filepath.Dir(a.Config.LedgerPath)
	hash := sha256.Sum256([]byte(filepath.Clean(a.Config.LedgerPath)))
	root = filepath.Join(root, "participant-flows-"+hex.EncodeToString(hash[:])[:16])
	if _, e := resources.PrivateRoot(root); e != nil {
		return domain.Err(503, "participant_flow_lock_unsafe")
	}
	fd, e := unix.Open(filepath.Join(root, id.Key()+".lock"), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return domain.Err(503, "participant_flow_lock_unsafe")
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
		return domain.Err(503, "participant_flow_lock_unsafe")
	}
	for {
		e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if e == nil {
			break
		}
		if !errors.Is(e, unix.EWOULDBLOCK) && !errors.Is(e, unix.EAGAIN) {
			return domain.Err(503, "participant_flow_lock_unsafe")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	return fn()
}
func (a *Agent) token(id executor.ExecutionIdentity) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tokens[id.Key()]
}
func (a *Agent) forget(id executor.ExecutionIdentity) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.tokens, id.Key())
	delete(a.logIdentities, id.Key())
}
func actorIdentity(actor Actor) executor.ExecutionIdentity {
	return executor.ExecutionIdentity{JobID: actor.JobID, AttemptID: actor.AttemptID, ComponentID: actor.ComponentID, Epoch: actor.Epoch}
}
func identityMap(id executor.ExecutionIdentity) map[string]any {
	return map[string]any{"job_id": id.JobID, "attempt_id": id.AttemptID, "component_id": id.ComponentID, "epoch": id.Epoch}
}
func strictInt(value any) (int64, bool) {
	switch v := value.(type) {
	case int:
		return int64(v), true
	case int64:
		return v, true
	case interface{ Int64() (int64, error) }:
		n, e := v.Int64()
		return n, e == nil
	}
	return 0, false
}
func (a *Agent) Receive(ctx context.Context, document map[string]any) (map[string]any, error) {
	for key := range document {
		if !contains([]string{"enrollment", "node_token", "node_certificate_thumbprint", "operation", "state_request"}, key) {
			return nil, domain.Err(422, "invalid_participant_dispatch")
		}
	}
	token := str(document["node_token"])
	if token == "" || len(token) > 16384 {
		return nil, domain.Err(401, "invalid_node_grant")
	}
	if thumb := str(document["node_certificate_thumbprint"]); thumb != "" && thumb != a.Config.NodeCertificateThumbprint {
		return nil, domain.Err(401, "invalid_node_grant")
	}
	actor, e := a.Broker.AuthenticateNode(ctx, "Bearer "+token, a.Config.NodeCertificateThumbprint, func(_ context.Context, p exchange.NodePrincipal) (bool, error) {
		return p.NodeID == a.Config.NodeID && p.PoolID == "external", nil
	})
	if e != nil {
		return nil, domain.Err(401, "invalid_node_grant")
	}
	id := actorIdentity(actor)
	lock := a.guardFor(id)
	lock.Lock()
	defer lock.Unlock()
	var out map[string]any
	e = a.withFlow(ctx, id, func() error {
		a.mu.Lock()
		a.tokens[id.Key()] = token
		a.mu.Unlock()
		var e error
		out, e = a.receive(ctx, actor, id, token, document)
		return e
	})
	return out, e
}
func (a *Agent) receive(ctx context.Context, actor Actor, id executor.ExecutionIdentity, token string, document map[string]any) (map[string]any, error) {
	op := str(document["operation"])
	if op == "" {
		op = "start"
	}
	switch op {
	case "publication-state":
		if e := checkScope(actor, "collect"); e != nil {
			return nil, e
		}
		request, ok := document["state_request"].(map[string]any)
		if !ok || len(request) != 2 {
			return nil, domain.Err(422, "invalid_publication_state_request")
		}
		maximum, ok := strictInt(request["max_bytes"])
		path := str(request["path"])
		if !ok || maximum < 1 || maximum > 1<<20 || !publicationPath(path) {
			return nil, domain.Err(422, "invalid_publication_state_request")
		}
		control, e := a.Client.Request(ctx, id, token, "control", nil)
		if e != nil {
			return nil, e
		}
		if !sameMap(control["identity"], identityMap(id)) || str(control["node_id"]) != a.Config.NodeID || control["termination_confirmed"] != true || control["revocation_confirmed"] != true {
			return nil, domain.Err(409, "participant_publication_fence_unconfirmed")
		}
		observation, e := a.Node.Inspect(ctx, id)
		if e != nil {
			return nil, e
		}
		if !observation.TerminationConfirmed {
			return nil, domain.Err(409, "participant_termination_unconfirmed")
		}
		root, e := a.Node.ReconciliationRoot(ctx, id)
		if e != nil {
			return nil, e
		}
		data, e := secureRead(root, path, maximum)
		if errors.Is(e, os.ErrNotExist) || errors.Is(e, unix.ENOENT) {
			return map[string]any{"identity": identityMap(id), "exists": false}, nil
		}
		if e != nil {
			return nil, domain.Err(503, "participant_publication_state_unavailable")
		}
		digest := sha256.Sum256(data)
		return map[string]any{"identity": identityMap(id), "exists": true, "content_base64": base64.StdEncoding.EncodeToString(data), "sha256": hex.EncodeToString(digest[:])}, nil
	case "purge":
		if len(actor.Scopes) != 1 || actor.Scopes[0] != "purge" {
			return nil, domain.Err(403, "node_scope_required")
		}
		if a.Cleanup == nil {
			return nil, domain.Err(503, "participant_cleanup_unavailable")
		}
		out, e := PurgeAssignment(ctx, a.Cleanup, actor, id, token)
		if e == nil {
			a.forget(id)
		}
		return out, e
	case "stop":
		return a.stop(ctx, actor, id, token)
	case "start":
		if e := checkScope(actor, "assignment"); e != nil {
			return nil, e
		}
		return a.start(ctx, actor, id, token, document)
	default:
		return nil, domain.Err(403, "node_scope_required")
	}
}
func (a *Agent) stop(ctx context.Context, actor Actor, id executor.ExecutionIdentity, token string) (map[string]any, error) {
	if e := checkScope(actor, "stopped"); e != nil {
		return nil, e
	}
	control, e := a.Client.Request(ctx, id, token, "control", nil)
	if e != nil {
		return nil, e
	}
	if str(control["node_id"]) != a.Config.NodeID || !sameMap(control["identity"], identityMap(id)) {
		return nil, domain.Err(403, "external_node_assignment_mismatch")
	}
	if control["termination_confirmed"] == true {
		a.forget(id)
		return map[string]any{"accepted": true, "state": "stopped"}, nil
	}
	neverStarted := false
	prior, e := a.Node.Inspect(ctx, id)
	if e == nil {
		neverStarted = prior.State == "RESERVED" && prior.TerminationConfirmed
	}
	var observed executor.RuntimeObservation
	observed, e = a.Node.Stop(ctx, id, 60)
	if e != nil {
		if executor.ErrorCode(e) != "missing_reservation" {
			return nil, e
		}
		absent, err := a.Node.ConfirmAbsent(ctx, id)
		if err != nil || !absent {
			return nil, domain.Err(503, "participant_termination_unconfirmed")
		}
		neverStarted = true
	} else {
		if !observed.TerminationConfirmed {
			return nil, domain.Err(503, "participant_termination_unconfirmed")
		}
		if _, e = a.PollLogs(ctx, id, token, 16, true); e != nil {
			return nil, e
		}
		released, e := a.Node.Release(ctx, id)
		if e != nil {
			return nil, e
		}
		if !released {
			return nil, domain.Err(503, "participant_termination_unconfirmed")
		}
	}
	if a.Config.ProxyStop != nil {
		stopped, e := a.Config.ProxyStop(ctx, id, true)
		if e != nil {
			return nil, e
		}
		if !stopped {
			return nil, domain.Err(503, "participant_proxy_termination_unconfirmed")
		}
	}
	if _, e = a.Client.Request(ctx, id, token, "stopped", map[string]any{"termination_confirmed": true, "never_started": neverStarted}); e != nil {
		return nil, e
	}
	a.forget(id)
	return map[string]any{"accepted": true, "state": "stopped"}, nil
}
func (a *Agent) start(ctx context.Context, actor Actor, id executor.ExecutionIdentity, token string, document map[string]any) (map[string]any, error) {
	plan, e := a.Client.Request(ctx, id, token, "plan", nil)
	if e != nil {
		return nil, e
	}
	if str(plan["node_id"]) != a.Config.NodeID || str(plan["pool_id"]) != "external" || !sameMap(plan["identity"], identityMap(id)) {
		return nil, domain.Err(403, "external_node_assignment_mismatch")
	}
	limits := mapv(plan["resources"])
	cpu, ok1 := strictInt(limits["cpu_millicores"])
	memory, ok2 := strictInt(limits["memory_bytes"])
	disk, ok3 := strictInt(limits["disk_bytes"])
	if !ok1 || !ok2 || !ok3 {
		return nil, domain.Err(422, "invalid_external_resources")
	}
	sourceLimits := map[string]int64{}
	for key, value := range mapv(plan["source_limits"]) {
		n, ok := strictInt(value)
		if !ok {
			return nil, domain.Err(422, "invalid_assignment")
		}
		sourceLimits[key] = n
	}
	specBytes, e := domain.CanonicalJSON(plan["job_spec"])
	if e != nil {
		return nil, e
	}
	spec, e := domain.DecodeJobSpec(specBytes)
	if e != nil {
		return nil, e
	}
	participant := str(plan["external_participant_id"])
	assignment := node.RemoteAssignment{Identity: id, NodeID: a.Config.NodeID, PoolID: "external", Resources: executor.ResourceLimits{CPUMillis: cpu, MemoryBytes: memory, DiskBytes: disk}.Defaults(), JobSpec: spec, ImageDigest: str(plan["image_digest"]), LeaseSeconds: floatNumber(plan["lease_seconds"]), ExternalParticipantID: &participant, SourceLimits: sourceLimits}
	if plan["deadline"] != nil {
		end := floatNumber(plan["deadline"])
		assignment.Deadline = &end
	}
	assignment = assignment.Defaults()
	if e = assignment.Validate(); e != nil {
		return nil, e
	}
	var existing executor.RuntimeObservation
	guarded, ok := a.Node.(interface {
		WithComponentGuardContext(context.Context, executor.ExecutionIdentity, bool, func(context.Context) error) error
	})
	if !ok {
		return nil, domain.Err(503, "participant_resource_guard_unavailable")
	}
	e = guarded.WithComponentGuardContext(ctx, id, false, func(guardCtx context.Context) error {
		prepared, e := a.Materializer.Plan(guardCtx, assignment)
		if e != nil {
			return e
		}
		reservation, e := a.Node.Reserve(guardCtx, prepared)
		if e != nil {
			return e
		}
		if !reservation.Acknowledged {
			return domain.Err(503, "participant_reservation_unconfirmed")
		}
		existing, e = a.Node.Inspect(guardCtx, id)
		if e != nil {
			return e
		}
		if !contains([]string{"EXITED", "STOPPED", "RELEASED"}, existing.State) {
			charged, e := a.Node.ChargeAuxiliaryBytes(guardCtx, id, 4*1024*1024+256*1024)
			if e != nil {
				return e
			}
			if !charged {
				return domain.Err(503, "participant_storage_unconfirmed")
			}
			_, e = a.Materializer.Reserve(guardCtx, assignment)
			if e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	if contains([]string{"EXITED", "STOPPED", "RELEASED"}, existing.State) {
		if !existing.TerminationConfirmed {
			return nil, domain.Err(503, "participant_termination_unconfirmed")
		}
		phase := "retry"
		if existing.State == "EXITED" {
			phase = "completed"
		}
		if _, e = a.Client.Request(ctx, id, token, "heartbeat", map[string]any{"phase": phase}); e != nil {
			return nil, e
		}
		return a.stop(ctx, actor, id, token)
	}
	binding, e := a.Materializer.Binding(ctx, id, str(plan["space_id"]), str(plan["principal_id"]))
	if e != nil {
		return nil, e
	}
	thumb := str(binding["certificate_thumbprint"])
	if thumb == "" {
		thumb = str(binding["cert_thumbprint"])
	}
	proxyID := str(binding["proxy_id"])
	if proxyID == "" {
		proxyID = str(binding["proxy_identifier"])
	}
	if proxyID == "" {
		proxyID = stableKey("external-proxy", id.Key())[:32]
	}
	if !validThumbprint(thumb) {
		return nil, domain.Err(422, "invalid_execution_certificate")
	}
	result, e := a.Client.Request(ctx, id, token, "assignment", map[string]any{"execution_certificate_thumbprint": thumb, "proxy_id": proxyID})
	if e != nil {
		return nil, e
	}
	runtime := mapv(result["runtime_config"])
	if !sameMap(result["identity"], identityMap(id)) || str(runtime["job_id"]) != id.JobID || str(runtime["attempt_id"]) != id.AttemptID || str(runtime["component_id"]) != id.ComponentID || number(runtime["epoch"]) != id.Epoch {
		return nil, domain.Err(403, "external_node_assignment_mismatch")
	}
	digest, e := spec.Digest()
	if e != nil {
		return nil, e
	}
	if str(runtime["spec_digest"]) != digest || !sameMap(runtime["spec"], spec.Map()) || !sameMap(runtime["source_manifest"], plan["source_manifest"]) {
		return nil, domain.Err(409, "participant_source_mismatch")
	}
	built := mapv(runtime["built_artifacts"])
	if !sameMap(built, mapv(plan["built_artifacts"])) {
		return nil, domain.Err(409, "participant_build_manifest_mismatch")
	}
	if len(built) > 0 {
		if e = a.stageProducts(ctx, id, token, built, disk); e != nil {
			return nil, e
		}
	}
	ready, e := a.Materializer.Prepare(ctx, id, runtime, binding)
	if e != nil {
		return nil, e
	}
	if !ready {
		return nil, domain.Err(503, "participant_preparation_unconfirmed")
	}
	observed, e := a.Node.Inspect(ctx, id)
	if e != nil {
		return nil, e
	}
	if contains([]string{"EXITED", "STOPPED", "RELEASED"}, observed.State) {
		if !observed.TerminationConfirmed {
			return nil, domain.Err(503, "participant_termination_unconfirmed")
		}
		phase := "retry"
		if observed.State == "EXITED" {
			phase = "completed"
		}
		if _, e = a.Client.Request(ctx, id, token, "heartbeat", map[string]any{"phase": phase}); e != nil {
			return nil, e
		}
		return a.stop(ctx, actor, id, token)
	}
	// Preparation is potentially slow. Online authority is rechecked immediately
	// before launch or extension; an old bootstrap token alone never starts work.
	if _, e = a.Client.Request(ctx, id, token, "credentials", map[string]any{}); e != nil {
		return nil, e
	}
	if !contains([]string{"RUNNING", "STARTING"}, observed.State) {
		observed, e = a.Node.Start(ctx, id)
	} else {
		e = a.Node.RenewLease(ctx, id, 120)
	}
	if e != nil {
		return nil, e
	}
	if _, e = a.Client.Request(ctx, id, token, "heartbeat", map[string]any{"phase": "running"}); e != nil {
		return nil, e
	}
	a.mu.Lock()
	a.logIdentities[id.Key()] = id
	a.mu.Unlock()
	return map[string]any{"accepted": true, "state": observed.State}, nil
}
func (a *Agent) stageProducts(ctx context.Context, id executor.ExecutionIdentity, token string, built map[string]any, disk int64) error {
	assignment, e := a.Materializer.Assignment(ctx, id)
	if e != nil {
		return e
	}
	if assignment.Identity != id || assignment.PoolID != "external" || assignment.ExternalParticipantID == nil {
		return domain.Err(403, "external_build_assignment_required")
	}
	approved := false
	for _, component := range assignment.JobSpec.Components {
		if component.Role == "build" {
			approved = true
		}
	}
	if !approved {
		return domain.Err(409, "external_build_not_approved")
	}
	total := int64(0)
	for filename, value := range built {
		descriptor := mapv(value)
		size, ok := strictInt(descriptor["size_bytes"])
		hash := str(descriptor["sha256"])
		validName, _ := regexp.MatchString("^[A-Za-z0-9][A-Za-z0-9_.+\\-]{0,240}\\.whl$", filename)
		hashBytes, hashError := hex.DecodeString(hash)
		if len(descriptor) != 2 || !ok || size < 1 || size > disk-total || !validName || len(hash) != 64 || hashError != nil || len(hashBytes) != 32 || strings.ToLower(hash) != hash {
			return domain.Err(422, "external_build_manifest_invalid")
		}
		total += size
	}
	streamer, ok := a.Client.(interface {
		Stream(context.Context, executor.ExecutionIdentity, string, string, int64, func(int64, []byte) error) error
	})
	if !ok {
		return domain.Err(503, "external_build_unavailable")
	}
	// Charge the source+wheel peak before a request or partial staging write.
	if e = a.Materializer.ReserveBuildInputs(ctx, id, built); e != nil {
		return e
	}
	names := make([]string, 0, len(built))
	for filename := range built {
		names = append(names, filename)
	}
	sort.Strings(names)
	for _, filename := range names {
		descriptor := mapv(built[filename])
		expected := str(descriptor["sha256"])
		size := number(descriptor["size_bytes"])
		hash := sha256.New()
		e = streamer.Stream(ctx, id, token, "build-products/"+filename, size, func(offset int64, data []byte) error {
			_, _ = hash.Write(data)
			accepted, e := a.Materializer.StageBuildInput(ctx, id, built, filename, offset, base64.StdEncoding.EncodeToString(data))
			if e != nil {
				return e
			}
			if !accepted {
				return domain.Err(503, "participant_build_stage_unconfirmed")
			}
			return nil
		})
		if e != nil {
			return e
		}
		if hex.EncodeToString(hash.Sum(nil)) != expected {
			return domain.Err(502, "external_build_hash_mismatch")
		}
	}
	return nil
}

func (a *Agent) DelegatedToken(ctx context.Context, id executor.ExecutionIdentity, audience string) (string, error) {
	if audience != "exchange" && audience != "gateway" {
		return "", domain.Err(422, "invalid_workload_audience")
	}
	token := a.token(id)
	if token == "" {
		return "", domain.Err(503, "external_node_grant_unavailable")
	}
	result, e := a.Client.Request(ctx, id, token, "credentials", map[string]any{})
	if e != nil {
		return "", e
	}
	key := audience + "_token"
	value := str(result[key])
	if value == "" || len(value) > 16384 {
		return "", domain.Err(502, "invalid_external_manager_reply")
	}
	return value, nil
}
func (a *Agent) PollLogs(ctx context.Context, id executor.ExecutionIdentity, token string, maxChunks int, terminal bool) (map[string]any, error) {
	if maxChunks < 1 || maxChunks > 16 {
		return nil, domain.Err(422, "invalid_log_poll_bound")
	}
	a.mu.Lock()
	offset := a.logOffsets[id.Key()]
	a.mu.Unlock()
	completed := false
	for i := 0; i < maxChunks; i++ {
		receipt, e := a.Node.ReadLogs(ctx, id, offset, 65536)
		if e != nil {
			return nil, e
		}
		response, e := a.Client.Request(ctx, id, token, "logs", receipt)
		if e != nil {
			return nil, e
		}
		next, ok := strictInt(response["next_offset"])
		produced, producedOK := strictInt(receipt["next_offset"])
		if response["accepted"] != true || !ok || !producedOK || next < 0 || next > 960*1024 || next < produced {
			return nil, domain.Err(502, "invalid_external_log_acknowledgment")
		}
		a.mu.Lock()
		a.logOffsets[id.Key()] = next
		a.mu.Unlock()
		completed = receipt["complete"] == true && response["complete"] == true
		prior := offset
		offset = next
		if completed || offset == prior {
			break
		}
	}
	if terminal && !completed {
		return nil, domain.Err(503, "participant_terminal_logs_unconfirmed")
	}
	return map[string]any{"next_offset": offset, "complete": completed}, nil
}
func (a *Agent) StartLogPolling(ctx context.Context, interval time.Duration) error {
	if interval < 50*time.Millisecond || interval > 60*time.Second {
		return domain.Err(422, "invalid_log_poll_interval")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancel != nil {
		return nil
	}
	ctx, a.cancel = context.WithCancel(ctx)
	a.done = make(chan struct{})
	go func() {
		defer close(a.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.mu.Lock()
				ids := make([]executor.ExecutionIdentity, 0, len(a.logIdentities))
				for _, id := range a.logIdentities {
					ids = append(ids, id)
				}
				a.mu.Unlock()
				for _, id := range ids {
					if ctx.Err() != nil {
						return
					}
					guard := a.guardFor(id)
					if !guard.TryLock() {
						continue
					}
					token := a.token(id)
					if token != "" {
						_, _ = a.PollLogs(ctx, id, token, 1, false)
					}
					guard.Unlock()
				}
			}
		}
	}()
	return nil
}
func (a *Agent) Close() {
	a.mu.Lock()
	cancel, done := a.cancel, a.done
	a.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}
func (a *Agent) Handler(managerThumbprints []string) http.Handler {
	approved := map[string]bool{}
	for _, thumb := range managerThumbprints {
		if validThumbprint(thumb) {
			approved[thumb] = true
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		fail := func(e error) {
			code, status := "participant_node_unavailable", 503
			var d *domain.Error
			if errors.As(e, &d) {
				code, status = d.Code, d.Status
			}
			w.WriteHeader(status)
			b, _ := domain.CanonicalJSON(map[string]any{"error": map[string]any{"code": code}})
			_, _ = w.Write(b)
		}
		if r.URL.Path != "/internal/nodes/v1/participants" {
			fail(domain.Err(404, "not_found"))
			return
		}
		if r.Method != "POST" {
			w.Header().Set("Allow", "POST")
			fail(domain.Err(405, "method_not_allowed"))
			return
		}
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			fail(domain.Err(401, "verified_manager_certificate_required"))
			return
		}
		fingerprint := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
		if !approved[base64.RawURLEncoding.EncodeToString(fingerprint[:])] {
			fail(domain.Err(401, "verified_manager_certificate_required"))
			return
		}
		lengths := r.Header.Values("Content-Length")
		if len(lengths) > 1 || (len(lengths) == 1 && (len(lengths[0]) > 10 || lengths[0] == "" || strings.IndexFunc(lengths[0], func(c rune) bool { return c < '0' || c > '9' }) >= 0)) {
			fail(domain.Err(400, "invalid_content_length"))
			return
		}
		if r.ContentLength > 1<<20 {
			fail(domain.Err(413, "request_too_large"))
			return
		}
		body, e := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		if e != nil || len(body) > 1<<20 {
			fail(domain.Err(413, "request_too_large"))
			return
		}
		decoded, e := domain.DecodeJSON(body)
		if e != nil {
			fail(domain.Err(422, "invalid_participant_dispatch"))
			return
		}
		document, ok := decoded.(map[string]any)
		if !ok {
			fail(domain.Err(422, "invalid_participant_dispatch"))
			return
		}
		result, e := a.Receive(r.Context(), document)
		if e != nil {
			fail(e)
			return
		}
		b, e := domain.CanonicalJSON(result)
		if e != nil {
			fail(domain.Err(503, "participant_node_unavailable"))
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write(b)
	})
}

// NodeToken exposes the current delegated token only to trusted in-process node
// transports. The exact identity, audience, certificate and expiry are rechecked.
func (a *Agent) NodeToken(ctx context.Context, id executor.ExecutionIdentity) (string, error) {
	token := a.token(id)
	if token == "" || len(token) > 16384 {
		return "", domain.Err(503, "external_node_grant_unavailable")
	}
	actor, e := a.Broker.AuthenticateNode(ctx, "Bearer "+token, a.Config.NodeCertificateThumbprint, func(_ context.Context, p exchange.NodePrincipal) (bool, error) {
		return p.NodeID == a.Config.NodeID && p.PoolID == "external" && p.JobID == id.JobID && p.AttemptID == id.AttemptID && p.ComponentID == id.ComponentID && p.Epoch == id.Epoch, nil
	})
	if e != nil || actor.GrantID == "" {
		return "", domain.Err(401, "invalid_node_grant")
	}
	return token, nil
}
