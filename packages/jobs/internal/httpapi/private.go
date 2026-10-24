package httpapi

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/auth"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
)

var privateIDPattern = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
var wheelNamePattern = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9_.+_-]{0,240}[.]whl$")
var nodeScopes = map[string]bool{"acknowledge": true, "heartbeat": true, "progress": true, "logs": true, "stopped": true, "collect": true, "reserve": true, "start": true, "inspect": true, "stop": true, "release": true, "renew": true, "assignment": true, "purge": true}

// VerifiedPeer uses only the certificate chain authenticated by Go's TLS stack.
// Forwarded certificate headers are deliberately ignored.
func VerifiedPeer(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return "", domain.Err(401, "verified_node_certificate_required")
	}
	certificate := r.TLS.VerifiedChains[0][0]
	if certificate == nil || len(certificate.Raw) == 0 {
		return "", domain.Err(401, "verified_node_certificate_required")
	}
	digest := sha256.Sum256(certificate.Raw)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}
func actorIdentity(actor ExecutionActor, id executor.ExecutionIdentity, scope string, peer string) error {
	if actor.JobID != id.JobID || actor.AttemptID != id.AttemptID || actor.ComponentID != id.ComponentID || actor.Epoch != id.Epoch {
		return domain.Err(404, "assignment_not_found")
	}
	if actor.CertificateThumbprint != "" && actor.CertificateThumbprint != peer {
		return domain.Err(401, "invalid_node_grant")
	}
	for _, candidate := range actor.Scopes {
		if candidate == scope {
			return nil
		}
	}
	return domain.Err(403, "node_scope_required")
}
func (s *Server) executionActor(r *http.Request, id executor.ExecutionIdentity, scope string, managed bool) (ExecutionActor, error) {
	peer, e := VerifiedPeer(r)
	if e != nil {
		return ExecutionActor{}, e
	}
	authenticate := s.options.NodeAuthenticate
	if managed {
		authenticate = s.options.ManagedAuthenticate
	}
	if authenticate == nil {
		if managed {
			return ExecutionActor{}, domain.Err(503, "managed_node_control_unavailable")
		}
		return ExecutionActor{}, domain.Err(503, "node_control_unavailable")
	}
	actor, e := authenticate(r.Context(), r.Header.Get("Authorization"), peer)
	if e != nil {
		return actor, e
	}
	return actor, actorIdentity(actor, id, scope, peer)
}
func (s *Server) private(w http.ResponseWriter, r *http.Request) error {
	path := strings.TrimPrefix(r.URL.Path, "/internal/jobs/v1/")
	if path == r.URL.Path {
		return domain.Err(404, "not_found")
	}
	parts := strings.Split(path, "/")
	if len(parts) < 6 {
		return domain.Err(404, "not_found")
	}
	mode := parts[0]
	if mode != "assignments" && mode != "nodes" && mode != "participants" {
		return domain.Err(404, "not_found")
	}
	epoch, e := strconv.ParseInt(parts[4], 10, 64)
	if e != nil {
		return domain.Err(422, "invalid_request")
	}
	id := executor.ExecutionIdentity{JobID: parts[1], AttemptID: parts[2], ComponentID: parts[3], Epoch: epoch}
	if e = id.Validate(); e != nil {
		return domain.Err(422, "invalid_request")
	}
	action := parts[5]
	if mode == "assignments" {
		if len(parts) != 6 {
			return domain.Err(404, "not_found")
		}
		return s.nodeControl(w, r, id, action)
	}
	if mode == "nodes" {
		if len(parts) != 6 {
			return domain.Err(404, "not_found")
		}
		return s.managedNode(w, r, id, action)
	}
	return s.externalParticipant(w, r, id, action, parts[6:])
}
func (s *Server) nodeControl(w http.ResponseWriter, r *http.Request, id executor.ExecutionIdentity, action string) error {
	scope := map[string]string{"ack": "acknowledge", "heartbeat": "heartbeat", "progress": "progress", "logs": "logs", "stopped": "stopped"}[action]
	if scope == "" {
		return domain.Err(404, "not_found")
	}
	if e := requireMethod(r, "POST"); e != nil {
		return e
	}
	if s.options.NodeCommand == nil || s.options.CheckAssignment == nil {
		return domain.Err(503, "node_control_unavailable")
	}
	actor, e := s.executionActor(r, id, scope, false)
	if e != nil {
		return e
	}
	valid, e := s.options.CheckAssignment(r.Context(), actor.NodeID, actor.PoolID, id)
	if e != nil {
		return e
	}
	if !valid {
		return domain.Err(404, "assignment_not_found")
	}
	body := map[string]any{}
	switch action {
	case "progress":
		body, e = jsonBody(r, "current_round", "phase", "publication_status", "metrics", "readiness")
		if e != nil {
			return e
		}
		if e = validateProgress(body); e != nil {
			return e
		}
	case "logs":
		body, e = jsonBody(r, "entries")
		if e != nil {
			return e
		}
		if e = validateLogEntries(body); e != nil {
			return e
		}
	}
	accepted, e := s.options.NodeCommand(r.Context(), action, id, body)
	if e != nil {
		return e
	}
	if !accepted {
		return domain.Err(409, "stale_assignment")
	}
	return writeJSON(w, 200, map[string]any{"accepted": true})
}
func (s *Server) managedNode(w http.ResponseWriter, r *http.Request, id executor.ExecutionIdentity, action string) error {
	methods := map[string]string{"bootstrap": "POST", "plan": "GET", "certificate": "POST", "credentials": "POST", "validate": "POST"}
	method := methods[action]
	if method == "" {
		return domain.Err(404, "not_found")
	}
	if e := requireMethod(r, method); e != nil {
		return e
	}
	if action == "bootstrap" {
		if s.options.ManagedBootstrap == nil {
			return domain.Err(503, "managed_node_control_unavailable")
		}
		peer, e := VerifiedPeer(r)
		if e != nil {
			return e
		}
		token, e := cookie(r, auth.SessionCookie)
		if e != nil {
			return e
		}
		if r.Header.Get("Authorization") != "" || token != "" {
			return domain.Err(401, "registered_node_certificate_required")
		}
		raw, e := io.ReadAll(r.Body)
		if e != nil {
			return domain.Err(422, "invalid_request")
		}
		if len(raw) > 0 {
			body, e := decodeObject(raw)
			if e != nil || len(body) > 0 {
				return domain.Err(422, "invalid_request")
			}
		}
		v, e := s.options.ManagedBootstrap(r.Context(), peer, id)
		if e != nil {
			return e
		}
		return writeJSON(w, 200, v)
	}
	if s.options.ManagedCall == nil {
		return domain.Err(503, "managed_node_control_unavailable")
	}
	actor, e := s.executionActor(r, id, "assignment", true)
	if e != nil {
		return e
	}
	body := map[string]any{}
	switch action {
	case "certificate":
		body, e = jsonBody(r, "csr_pem", "space_id", "principal_id")
		if e != nil {
			return e
		}
		if e = validateCertificate(body); e != nil {
			return e
		}
	case "credentials":
		body, e = jsonBody(r, "certificate_thumbprint", "audience")
		if e != nil {
			return e
		}
		if !thumbPattern.MatchString(text(body["certificate_thumbprint"])) || (text(body["audience"]) != "exchange" && text(body["audience"]) != "gateway") {
			return domain.Err(422, "invalid_request")
		}
	case "validate":
		body, e = jsonBody(r, "node_id", "pool_id", "grant_id", "certificate_thumbprint", "scopes", "resources")
		if e != nil {
			return e
		}
		if e = validateNodeRequest(body); e != nil {
			return e
		}
	}
	v, e := s.options.ManagedCall(r.Context(), action, actor, id, body)
	if e != nil {
		return e
	}
	return writeJSON(w, 200, v)
}
func (s *Server) externalParticipant(w http.ResponseWriter, r *http.Request, id executor.ExecutionIdentity, action string, tail []string) error {
	method := map[string]string{"plan": "GET", "control": "GET", "heartbeat": "POST", "assignment": "POST", "certificate": "POST", "credentials": "POST", "stopped": "POST", "logs": "POST", "purge-plan": "GET", "purged": "POST", "build-products": "GET", "source": "GET"}[action]
	if method == "" {
		return domain.Err(404, "not_found")
	}
	if action != "build-products" && action != "source" && len(tail) > 0 {
		return domain.Err(404, "not_found")
	}
	if e := requireMethod(r, method); e != nil {
		return e
	}
	if s.options.ParticipantCall == nil {
		return domain.Err(503, "participant_enrollment_unavailable")
	}
	scope := "assignment"
	switch action {
	case "control", "stopped":
		scope = "stopped"
	case "heartbeat":
		scope = "heartbeat"
	case "logs":
		scope = "logs"
	case "purge-plan", "purged":
		scope = "purge"
	}
	actor, e := s.executionActor(r, id, scope, false)
	if e != nil {
		return e
	}
	if action == "build-products" || action == "source" {
		return s.participantFile(w, r, id, actor, action, tail)
	}
	body := map[string]any{}
	switch action {
	case "heartbeat":
		body, e = jsonBody(r, "phase", "current_round")
		if e != nil {
			return e
		}
		if _, ok := body["phase"]; !ok {
			body["phase"] = "running"
		}
		if !oneOf(text(body["phase"]), "running", "waiting_initialization", "waiting_for_model", "training", "publishing", "completed", "retry", "needs_attention", "stopped") {
			return domain.Err(422, "invalid_request")
		}
		if v, ok := body["current_round"]; ok && v != nil {
			n, valid := integer(v)
			if !valid || n < 0 || n > 1000000 {
				return domain.Err(422, "invalid_request")
			}
		}
	case "assignment":
		body, e = jsonBody(r, "execution_certificate_thumbprint", "proxy_id")
		if e != nil {
			return e
		}
		if !thumbPattern.MatchString(text(body["execution_certificate_thumbprint"])) || !domain.ValidIdentifier(text(body["proxy_id"])) {
			return domain.Err(422, "invalid_request")
		}
	case "certificate":
		body, e = jsonBody(r, "csr_pem", "space_id", "principal_id")
		if e != nil {
			return e
		}
		if e = validateCertificate(body); e != nil {
			return e
		}
	case "stopped":
		body, e = jsonBody(r, "termination_confirmed", "never_started")
		if e != nil {
			return e
		}
		if _, ok := body["termination_confirmed"]; !ok {
			body["termination_confirmed"] = true
		}
		if body["termination_confirmed"] != true {
			return domain.Err(422, "invalid_request")
		}
		if v, ok := body["never_started"]; ok {
			if _, ok := v.(bool); !ok {
				return domain.Err(422, "invalid_request")
			}
		} else {
			body["never_started"] = false
		}
	case "logs":
		body, e = jsonBody(r, "identity", "source_id", "offset", "next_offset", "content", "complete", "truncated")
		if e != nil {
			return e
		}
		if e = validateExternalLogs(body, id); e != nil {
			return e
		}
	case "purged":
		body, e = jsonBody(r, "confirmed")
		if e != nil {
			return e
		}
		if body["confirmed"] != true {
			return domain.Err(422, "invalid_request")
		}
	}
	v, e := s.options.ParticipantCall(r.Context(), action, actor, id, body)
	if e != nil {
		return e
	}
	return writeJSON(w, 200, v)
}
func (s *Server) participantFile(w http.ResponseWriter, r *http.Request, id executor.ExecutionIdentity, actor ExecutionActor, action string, tail []string) error {
	if s.options.ParticipantOpen == nil || s.options.ParticipantAccessValid == nil {
		return domain.Err(503, "participant_enrollment_unavailable")
	}
	relative := strings.Join(tail, "/")
	if action == "build-products" {
		if len(tail) != 1 || !wheelNamePattern.MatchString(relative) {
			return domain.Err(422, "invalid_build_product_name")
		}
	} else {
		if relative == "" || utf8.RuneCountInString(relative) > 1024 || strings.HasPrefix(relative, "/") || strings.Contains(relative, "\\") {
			return domain.Err(422, "invalid_source_path")
		}
		for _, piece := range tail {
			if piece == "" || piece == "." || piece == ".." {
				return domain.Err(422, "invalid_source_path")
			}
		}
	}
	file, e := s.options.ParticipantOpen(r.Context(), action, actor, relative)
	if e != nil {
		return e
	}
	badCode := "invalid_source_descriptor"
	fallback := "source.bin"
	if action == "build-products" {
		badCode = "invalid_build_product_descriptor"
		fallback = "build.whl"
	}
	if file == nil || file.Reader == nil || file.SizeBytes < 0 || !shaPattern.MatchString(file.SHA256) {
		if file != nil && file.Reader != nil {
			file.Reader.Close()
		}
		return domain.Err(502, badCode)
	}
	defer file.Reader.Close()
	filename := tail[len(tail)-1]
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(file.SizeBytes, 10))
	w.Header().Set("X-Content-SHA256", file.SHA256)
	w.Header().Set("Content-Disposition", "attachment; filename="+fallback+"; filename*=UTF-8''"+rfc5987(filename))
	started, streamErr := streamVerified(w, file.Reader, file.SizeBytes, file.SHA256, func() error {
		fresh, authErr := s.executionActor(r, id, "assignment", false)
		if authErr != nil {
			return authErr
		}
		current, accessErr := s.options.ParticipantAccessValid(r.Context(), action, fresh)
		if accessErr != nil {
			return accessErr
		}
		if !current {
			return domain.Err(404, "assignment_not_found")
		}
		return nil
	})
	return transferFailure(w, started, streamErr, badCode)
}
func oneOf(value string, options ...string) bool {
	for _, option := range options {
		if value == option {
			return true
		}
	}
	return false
}
func validateProgress(body map[string]any) error {
	nonempty := false
	for key, value := range body {
		if value == nil {
			delete(body, key)
			continue
		}
		nonempty = true
		switch key {
		case "current_round":
			n, ok := integer(value)
			if !ok || n < 0 || n > 1000000 {
				return domain.Err(422, "invalid_request")
			}
		case "phase":
			if !oneOf(text(value), "fetching", "building", "initializing", "aggregating", "waiting_participants", "training", "publishing", "collecting_results") {
				return domain.Err(422, "invalid_request")
			}
		case "publication_status":
			if !oneOf(text(value), "none", "absent", "confirmed", "published", "unknown", "publishing", "ambiguous", "not_observed") {
				return domain.Err(422, "invalid_request")
			}
		case "readiness":
			if !oneOf(text(value), "initializing", "waiting", "ready", "training", "finished", "failed") {
				return domain.Err(422, "invalid_request")
			}
		case "metrics":
			metrics, ok := value.(map[string]any)
			if !ok || len(metrics) > 32 {
				return domain.Err(422, "invalid_request")
			}
			for name, entry := range metrics {
				n, ok := entry.(json.Number)
				if !ok || name == "" || utf8.RuneCountInString(name) > 64 {
					return domain.Err(422, "invalid_request")
				}
				f, e := n.Float64()
				if e != nil || math.IsNaN(f) || math.IsInf(f, 0) {
					return domain.Err(422, "invalid_request")
				}
			}
		}
	}
	if !nonempty {
		return domain.Err(422, "invalid_request")
	}
	return nil
}
func validateLogEntries(body map[string]any) error {
	entries, ok := body["entries"].([]any)
	if !ok || len(entries) < 1 || len(entries) > 100 {
		return domain.Err(422, "invalid_request")
	}
	total := len(entries) - 1
	for _, entry := range entries {
		line, ok := entry.(string)
		if !ok {
			return domain.Err(422, "invalid_request")
		}
		if len(line) > 8192 {
			return domain.Err(413, "log_line_too_large")
		}
		total += len(line)
	}
	if total > 65536 {
		return domain.Err(413, "log_batch_too_large")
	}
	return nil
}
func validateCertificate(body map[string]any) error {
	csr := text(body["csr_pem"])
	if len(csr) > 16384 || !strings.HasPrefix(csr, "-----BEGIN CERTIFICATE REQUEST-----\n") || !strings.HasSuffix(strings.TrimSpace(csr), "-----END CERTIFICATE REQUEST-----") {
		return domain.Err(422, "invalid_request")
	}
	if !domain.ValidIdentifier(text(body["space_id"])) || !shaPattern.MatchString(text(body["principal_id"])) {
		return domain.Err(422, "invalid_request")
	}
	return nil
}
func validateNodeRequest(body map[string]any) error {
	for _, key := range []string{"node_id", "pool_id", "grant_id"} {
		if !privateIDPattern.MatchString(text(body[key])) {
			return domain.Err(422, "invalid_request")
		}
	}
	if !thumbPattern.MatchString(text(body["certificate_thumbprint"])) {
		return domain.Err(422, "invalid_request")
	}
	scopes, ok := body["scopes"].([]any)
	if !ok || len(scopes) < 1 || len(scopes) > 32 {
		return domain.Err(422, "invalid_request")
	}
	seen := map[string]bool{}
	for _, item := range scopes {
		scope, ok := item.(string)
		if !ok || !nodeScopes[scope] || seen[scope] {
			return domain.Err(422, "invalid_request")
		}
		seen[scope] = true
	}
	resources, ok := body["resources"].(map[string]any)
	if !ok || len(resources) != 3 {
		return domain.Err(422, "invalid_request")
	}
	for _, key := range []string{"cpu_millicores", "memory_bytes", "disk_bytes"} {
		n, ok := integer(resources[key])
		max := int64(1 << 50)
		if key == "cpu_millicores" {
			max = 1000000
		}
		if !ok || n < 0 || n > max {
			return domain.Err(422, "invalid_request")
		}
	}
	return nil
}
func validateExternalLogs(body map[string]any, id executor.ExecutionIdentity) error {
	identity, ok := body["identity"].(map[string]any)
	if !ok || len(identity) != 4 {
		return domain.Err(422, "invalid_request")
	}
	epoch, ok := integer(identity["epoch"])
	if !ok || !domain.ValidIdentifier(text(identity["job_id"])) || !domain.ValidIdentifier(text(identity["attempt_id"])) || !domain.ValidIdentifier(text(identity["component_id"])) || epoch < 1 {
		return domain.Err(422, "invalid_request")
	}
	supplied := executor.ExecutionIdentity{JobID: text(identity["job_id"]), AttemptID: text(identity["attempt_id"]), ComponentID: text(identity["component_id"]), Epoch: epoch}
	if supplied != id {
		return domain.Err(404, "assignment_not_found")
	}
	if text(body["source_id"]) != id.Key() {
		return domain.Err(422, "invalid_request")
	}
	offset, ok := integer(body["offset"])
	if !ok || offset < 0 || offset > 1048576 {
		return domain.Err(422, "invalid_request")
	}
	next, ok := integer(body["next_offset"])
	if !ok || next < 0 || next > 1048576 {
		return domain.Err(422, "invalid_request")
	}
	content, ok := body["content"].(string)
	if !ok || len(content) > 65536 || next != offset+int64(len(content)) {
		return domain.Err(422, "invalid_request")
	}
	for _, key := range []string{"complete", "truncated"} {
		if _, ok := body[key].(bool); !ok {
			return domain.Err(422, "invalid_request")
		}
	}
	return nil
}
