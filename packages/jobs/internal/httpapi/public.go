package httpapi

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/auth"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

func (s *Server) route(w http.ResponseWriter, r *http.Request) error {
	path := r.URL.Path
	if strings.HasPrefix(path, "/internal/") {
		if s.options.PublicOnly {
			return domain.Err(404, "not_found")
		}
		return s.private(w, r)
	}
	if s.options.PrivateOnly && path != "/healthz" && path != "/readyz" {
		return domain.Err(404, "not_found")
	}
	switch path {
	case "/healthz":
		if e := requireMethod(r, "GET"); e != nil {
			return e
		}
		return writeJSON(w, 200, map[string]any{"status": "ok"})
	case "/readyz":
		if e := requireMethod(r, "GET"); e != nil {
			return e
		}
		if s.options.Readiness != nil {
			if e := s.options.Readiness(r.Context()); e != nil {
				return domain.Err(503, "not_ready")
			}
		} else if _, e := s.manager.DB.CheckSchema(r.Context()); e != nil {
			return domain.Err(503, "not_ready")
		}
		return writeJSON(w, 200, map[string]any{"status": "ready"})
	case "/", "/dashboard":
		if r.Method != "GET" && r.Method != "HEAD" {
			return domain.Err(405, "http_error")
		}
		http.Redirect(w, r, "/dashboard/", 303)
		return nil
	case "/auth/login":
		return s.login(w, r)
	case "/auth/callback":
		return s.callback(w, r)
	case "/auth/logout":
		return s.logout(w, r)
	case "/auth/backchannel-logout":
		return s.backchannel(w, r)
	case "/auth/session", Prefix + "/session":
		return s.session(w, r)
	}
	if strings.HasPrefix(path, "/dashboard/") {
		if r.Method != "GET" && r.Method != "HEAD" {
			return domain.Err(405, "http_error")
		}
		if s.static == nil {
			return domain.Err(404, "not_found")
		}
		relative := strings.TrimPrefix(path, "/dashboard/")
		if relative == "" {
			relative = "index.html"
		}
		if !fs.ValidPath(relative) || strings.HasPrefix(relative, ".") || strings.Contains(relative, "/.") {
			return domain.Err(404, "not_found")
		}
		if info, e := fs.Stat(s.options.Dashboard, relative); e != nil || info.IsDir() {
			return domain.Err(404, "not_found")
		}
		clone := r.Clone(r.Context())
		u := *r.URL
		clone.URL = &u
		clone.URL.Path = "/" + relative
		if path == "/dashboard/" {
			clone.URL.Path = "/"
		}
		s.static.ServeHTTP(w, clone)
		return nil
	}
	if !strings.HasPrefix(path, Prefix+"/") {
		return domain.Err(404, "not_found")
	}
	if path == Prefix+"/events/stream" {
		return s.eventsStream(w, r)
	}
	return s.publicAPI(w, r, strings.Split(strings.TrimPrefix(path, Prefix+"/"), "/"))
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) error {
	if e := requireMethod(r, "GET"); e != nil {
		return e
	}
	start, e := s.auth.BeginLogin(r.Context())
	if e != nil {
		return e
	}
	http.SetCookie(w, &http.Cookie{Name: auth.LoginCookie, Value: start.StateCookie, Path: "/", MaxAge: 600, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, start.AuthorizationURL, 303)
	return nil
}
func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(0, 0), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}
func (s *Server) callback(w http.ResponseWriter, r *http.Request) error {
	if e := requireMethod(r, "GET"); e != nil {
		return e
	}
	q := r.URL.Query()
	for k, max := range map[string]int{"code": 8192, "state": 1024, "error": 256} {
		v := q.Get(k)
		if utf8.RuneCountInString(v) > max || (k != "error" && q.Has(k) && v == "") {
			return domain.Err(422, "invalid_request")
		}
	}
	clearCookie(w, auth.LoginCookie)
	if q.Get("error") != "" || q.Get("code") == "" || q.Get("state") == "" {
		return domain.Err(400, "invalid_authorization_response")
	}
	stateCookie, e := cookie(r, auth.LoginCookie)
	if e != nil {
		return e
	}
	issue, e := s.auth.FinishLogin(r.Context(), q.Get("code"), q.Get("state"), stateCookie)
	if e != nil {
		return e
	}
	http.SetCookie(w, &http.Cookie{Name: auth.SessionCookie, Value: issue.SessionToken, Path: "/", MaxAge: 8 * 3600, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/dashboard/", 303)
	return nil
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) error {
	if e := requireMethod(r, "POST"); e != nil {
		return e
	}
	token, e := cookie(r, auth.SessionCookie)
	if e != nil {
		return e
	}
	if e = s.auth.Logout(r.Context(), token, r.Header.Get("X-CSRF-Token"), r.Header.Get("Origin")); e != nil {
		return e
	}
	clearCookie(w, auth.SessionCookie)
	return writeJSON(w, 200, map[string]any{"authenticated": false})
}
func (s *Server) backchannel(w http.ResponseWriter, r *http.Request) error {
	if e := requireMethod(r, "POST"); e != nil {
		return e
	}
	if strings.ToLower(strings.Split(r.Header.Get("Content-Type"), ";")[0]) != "application/x-www-form-urlencoded" {
		return domain.Err(415, "logout_form_required")
	}
	data, e := io.ReadAll(r.Body)
	if e != nil || !utf8.Valid(data) {
		return domain.Err(400, "invalid_logout_request")
	}
	fields, e := url.ParseQuery(string(data))
	if e != nil || len(fields) != 1 || len(fields["logout_token"]) != 1 {
		return domain.Err(400, "invalid_logout_request")
	}
	token := fields.Get("logout_token")
	if len(token) < 1 || len(token) > 16384 {
		return domain.Err(400, "invalid_logout_request")
	}
	if e = s.auth.BackchannelLogout(r.Context(), token); e != nil {
		return e
	}
	return writeJSON(w, 200, map[string]any{"accepted": true})
}
func (s *Server) session(w http.ResponseWriter, r *http.Request) error {
	if e := requireMethod(r, "GET"); e != nil {
		return e
	}
	token, e := cookie(r, auth.SessionCookie)
	if e != nil {
		return e
	}
	if token != "" {
		v, e := s.auth.SessionInfo(r.Context(), token)
		if e != nil {
			return e
		}
		return writeJSON(w, 200, v)
	}
	if r.Header.Get("Authorization") == "" {
		return writeJSON(w, 200, map[string]any{"authenticated": false, "login_url": "/auth/login"})
	}
	actor, e := s.actor(r, false, true)
	if e != nil {
		return e
	}
	permissions := []string{}
	if actor.PlatformOperator {
		permissions = append(permissions, "platform_operator")
	}
	return writeJSON(w, 200, map[string]any{"authenticated": true, "principal": map[string]any{"principal_id": actor.ID, "display_name": actor.Subject}, "permissions": permissions, "csrf_token": nil, "login_url": "/auth/login"})
}
func (s *Server) publicAPI(w http.ResponseWriter, r *http.Request, parts []string) error {
	methods := publicMethods(parts)
	if len(methods) == 0 {
		return domain.Err(404, "not_found")
	}
	if !oneOf(r.Method, methods...) {
		return domain.Err(405, "http_error")
	}
	mutating := r.Method != "GET" && r.Method != "HEAD"
	actor, e := s.actor(r, mutating, true)
	if e != nil {
		return e
	}
	ctx := r.Context()
	if len(parts) == 1 && parts[0] == "catalog" {
		if e = requireMethod(r, "GET"); e != nil {
			return e
		}
		v, e := s.manager.Catalog(ctx, actor.ID)
		if e != nil {
			return e
		}
		return writeJSON(w, 200, v)
	}
	if parts[0] == "pools" {
		return s.pools(w, r, actor, parts)
	}
	if parts[0] != "jobs" {
		return domain.Err(404, "not_found")
	}
	if len(parts) == 1 {
		switch r.Method {
		case "POST":
			if !jsonMediaType(r) {
				return domain.Err(422, "invalid_request")
			}
			raw, e := io.ReadAll(r.Body)
			if e != nil {
				return domain.Err(422, "invalid_request")
			}
			if _, e = decodeObject(raw); e != nil {
				return domain.Err(422, "invalid_request")
			}
			spec, e := domain.DecodeJobSpec(raw)
			if e != nil {
				return domain.Err(422, "invalid_request")
			}
			key, e := idempotency(r)
			if e != nil {
				return e
			}
			v, e := s.manager.CreateJob(ctx, actor.ID, spec, key)
			if e != nil {
				return e
			}
			return view(w, 202, v, Prefix+"/jobs/"+url.PathEscape(text(v["id"])))
		case "GET":
			q := r.URL.Query()
			limit, e := queryInt(q, "limit", 50, 1, 100)
			if e != nil {
				return e
			}
			cursor, e := queryText(q, "cursor", 4096)
			if e != nil {
				return e
			}
			filters := map[string]any{"view": "all"}
			if q.Has("view") {
				v := q.Get("view")
				if v != "all" && v != "current" && v != "queued" && v != "history" {
					return domain.Err(422, "invalid_request")
				}
				filters["view"] = v
			}
			for name, max := range map[string]int{"state": 64, "project_id": 128, "search": 200} {
				if q.Has(name) {
					v, e := queryText(q, name, max)
					if e != nil {
						return e
					}
					filters[name] = v
				}
			}
			v, e := s.manager.ListJobs(ctx, actor.ID, filters, limit, cursor)
			if e != nil {
				return e
			}
			return writeJSON(w, 200, v)
		default:
			return domain.Err(405, "http_error")
		}
	}
	id := parts[1]
	if id == "" {
		return domain.Err(404, "not_found")
	}
	if len(parts) == 2 {
		if e = requireMethod(r, "GET"); e != nil {
			return e
		}
		v, e := s.manager.GetJob(ctx, actor.ID, id)
		if e != nil {
			return e
		}
		return view(w, 200, v, "")
	}
	if len(parts) == 5 && parts[2] == "participants" {
		return s.enrollment(w, r, actor.ID, id, parts[3], parts[4])
	}
	if parts[2] == "artifacts" {
		return s.artifact(w, r, actor.ID, id, parts[3:])
	}
	if parts[2] == "members" {
		return s.members(w, r, actor.ID, id, parts[3:])
	}
	if len(parts) != 3 {
		return domain.Err(404, "not_found")
	}
	switch parts[2] {
	case "attempts":
		if e = requireMethod(r, "GET"); e != nil {
			return e
		}
		v, e := s.manager.ListAttempts(ctx, actor.ID, id)
		if e != nil {
			return e
		}
		return writeJSON(w, 200, v)
	case "events", "logs":
		if e = requireMethod(r, "GET"); e != nil {
			return e
		}
		q := r.URL.Query()
		limit, e := queryInt(q, "limit", 100, 1, 100)
		if e != nil {
			return e
		}
		cursor, e := queryText(q, "cursor", 4096)
		if e != nil {
			return e
		}
		if parts[2] == "events" {
			v, e := s.manager.ListEvents(ctx, actor.ID, id, limit, cursor)
			if e != nil {
				return e
			}
			return writeJSON(w, 200, v)
		}
		component, e := queryText(q, "component", 128)
		if e != nil {
			return e
		}
		var attempt *int64
		if q.Has("attempt") {
			n, e := queryInt(q, "attempt", 0, 1, 9223372036854775807)
			if e != nil {
				return e
			}
			a := int64(n)
			attempt = &a
		}
		v, e := s.manager.ListLogs(ctx, actor.ID, id, limit, cursor, component, attempt)
		if e != nil {
			return e
		}
		return writeJSON(w, 200, v)
	case "cancel", "retry", "purge", "reconcile":
		if e = requireMethod(r, "POST"); e != nil {
			return e
		}
		expected, e := version(r)
		if e != nil {
			return e
		}
		key, e := idempotency(r)
		if e != nil {
			return e
		}
		var value map[string]any
		switch parts[2] {
		case "cancel":
			value, e = s.manager.Cancel(ctx, actor.ID, id, expected, key)
		case "retry":
			value, e = s.manager.Retry(ctx, actor.ID, id, expected, key)
		case "purge":
			value, e = s.manager.Purge(ctx, actor.ID, id, expected, key)
		case "reconcile":
			body, err := jsonBody(r, "evidence")
			if err != nil {
				return err
			}
			evidence, ok := body["evidence"].(map[string]any)
			if !ok {
				return domain.Err(422, "invalid_request")
			}
			value, e = s.manager.Reconcile(ctx, actor.ID, id, expected, key, evidence)
		}
		if e != nil {
			return e
		}
		return view(w, 202, value, "")
	}
	return domain.Err(404, "not_found")
}
func (s *Server) members(w http.ResponseWriter, r *http.Request, actor, id string, tail []string) error {
	ctx := r.Context()
	if len(tail) == 0 {
		if e := requireMethod(r, "GET"); e != nil {
			return e
		}
		v, e := s.manager.ListMembers(ctx, actor, id)
		if e != nil {
			return e
		}
		return writeJSON(w, 200, v)
	}
	if len(tail) != 1 || tail[0] == "" {
		return domain.Err(404, "not_found")
	}
	if r.Method != "PUT" && r.Method != "DELETE" {
		return domain.Err(405, "http_error")
	}
	expected, e := version(r)
	if e != nil {
		return e
	}
	key, e := idempotency(r)
	if e != nil {
		return e
	}
	var v map[string]any
	if r.Method == "DELETE" {
		v, e = s.manager.DeleteMember(ctx, actor, id, tail[0], expected, key)
	} else {
		body, err := jsonBody(r, "role")
		if err != nil {
			return err
		}
		role := text(body["role"])
		if role != "reader" && role != "operator" && role != "admin" {
			return domain.Err(422, "invalid_request")
		}
		v, e = s.manager.PutMember(ctx, actor, id, tail[0], role, expected, key)
	}
	if e != nil {
		return e
	}
	return view(w, 200, v, "")
}
func (s *Server) pools(w http.ResponseWriter, r *http.Request, actor auth.Principal, parts []string) error {
	if len(parts) == 1 {
		if e := requireMethod(r, "GET"); e != nil {
			return e
		}
		v, e := s.manager.ListPools(r.Context(), actor.ID)
		if e != nil {
			return e
		}
		return writeJSON(w, 200, v)
	}
	if len(parts) != 2 || parts[1] == "" {
		return domain.Err(404, "not_found")
	}
	if e := requireMethod(r, "PUT"); e != nil {
		return e
	}
	body, e := jsonBody(r, "name", "node_id", "cpu_millicores", "memory_bytes", "disk_bytes", "gpu_uuids", "sandbox_profiles", "gpu_profiles", "healthy", "quarantined")
	if e != nil {
		return e
	}
	for key, value := range body {
		if value == nil {
			delete(body, key)
			continue
		}
		switch key {
		case "name", "node_id":
			str, ok := value.(string)
			max := 200
			if key == "node_id" {
				max = 128
			}
			if !ok || str == "" || utf8.RuneCountInString(str) > max {
				return domain.Err(422, "invalid_request")
			}
		case "cpu_millicores", "memory_bytes", "disk_bytes":
			n, ok := integer(value)
			max := int64(1 << 50)
			if key == "cpu_millicores" {
				max = 1000000
			}
			if !ok || n < 0 || n > max {
				return domain.Err(422, "invalid_request")
			}
		case "healthy", "quarantined":
			if _, ok := value.(bool); !ok {
				return domain.Err(422, "invalid_request")
			}
		case "gpu_uuids", "sandbox_profiles", "gpu_profiles":
			a, ok := value.([]any)
			max := 128
			if key == "gpu_uuids" {
				max = 1024
			}
			if !ok || len(a) > max {
				return domain.Err(422, "invalid_request")
			}
			for _, entry := range a {
				if _, ok := entry.(string); !ok {
					return domain.Err(422, "invalid_request")
				}
			}
		}
	}
	if r.Header.Get("If-Match") != "" {
		n, e := version(r)
		if e != nil {
			return e
		}
		body["expected_version"] = n
	}
	v, e := s.manager.PutPool(r.Context(), actor.ID, parts[1], body)
	if e != nil {
		return e
	}
	return view(w, 200, v, "")
}
func (s *Server) artifact(w http.ResponseWriter, r *http.Request, actor, id string, tail []string) error {
	if e := requireMethod(r, "GET"); e != nil {
		return e
	}
	ctx := r.Context()
	if len(tail) == 0 {
		limit, e := queryInt(r.URL.Query(), "limit", 100, 1, 100)
		if e != nil {
			return e
		}
		cursor, e := queryText(r.URL.Query(), "cursor", 4096)
		if e != nil {
			return e
		}
		v, e := s.manager.ListArtifacts(ctx, actor, id, limit, cursor)
		if e != nil {
			return e
		}
		if s.options.ArtifactBroker == nil {
			switch items := v["items"].(type) {
			case []map[string]any:
				for _, item := range items {
					item["download_available"] = false
					item["unavailable_reason"] = "artifact_broker_unavailable"
				}
			case []any:
				for _, entry := range items {
					if item, ok := entry.(map[string]any); ok {
						item["download_available"] = false
						item["unavailable_reason"] = "artifact_broker_unavailable"
					}
				}
			}
		}
		return writeJSON(w, 200, v)
	}
	if len(tail) == 1 {
		v, e := s.manager.GetArtifact(ctx, actor, id, tail[0])
		if e != nil {
			return e
		}
		if s.options.ArtifactBroker == nil {
			v["download_available"] = false
			v["unavailable_reason"] = "artifact_broker_unavailable"
		}
		return writeJSON(w, 200, v)
	}
	if len(tail) != 2 || tail[1] != "download" {
		return domain.Err(404, "not_found")
	}
	metadata, e := s.manager.GetArtifact(ctx, actor, id, tail[0])
	if e != nil {
		return e
	}
	if s.options.ArtifactBroker == nil {
		return domain.Err(503, "artifact_broker_unavailable")
	}
	download, e := s.options.ArtifactBroker.OpenAuthorized(ctx, actor, id, tail[0])
	if e != nil {
		return e
	}
	if download == nil || download.Reader == nil || download.Size < 0 {
		if download != nil && download.Reader != nil {
			download.Reader.Close()
		}
		return domain.Err(502, "invalid_artifact_descriptor")
	}
	defer download.Reader.Close()
	w.Header().Set("Content-Disposition", "attachment; filename=artifact.bin; filename*=UTF-8''"+rfc5987(download.Name))
	w.Header().Set("Content-Length", strconv.FormatInt(download.Size, 10))
	w.Header().Set("Content-Type", "application/octet-stream")
	started, streamErr := streamVerified(w, download.Reader, download.Size, text(metadata["sha256"]), func() error {
		fresh, authErr := s.actor(r, false, false)
		if authErr != nil {
			return authErr
		}
		if fresh.ID != actor {
			return domain.Err(401, "invalid_session")
		}
		current, accessErr := s.manager.GetArtifact(ctx, fresh.ID, id, tail[0])
		if accessErr != nil {
			return accessErr
		}
		if current["download_available"] != true {
			return domain.Err(410, "artifact_unavailable")
		}
		return nil
	})
	return transferFailure(w, started, streamErr, "artifact_integrity_failed")
}
func rfc5987(value string) string { return strings.ReplaceAll(url.QueryEscape(value), "+", "%20") }
func (s *Server) enrollment(w http.ResponseWriter, r *http.Request, actor, id, participant, action string) error {
	if action == "enrollment" {
		if e := requireMethod(r, "GET"); e != nil {
			return e
		}
		if s.options.ParticipantEnrollment == nil {
			if _, e := s.manager.GetJob(r.Context(), actor, id); e != nil {
				return e
			}
			return domain.Err(503, "participant_enrollment_unavailable")
		}
		v, e := s.options.ParticipantEnrollment(r.Context(), actor, id, participant)
		if e != nil {
			return e
		}
		return writeJSON(w, 200, v)
	}
	if action != "enroll" {
		return domain.Err(404, "not_found")
	}
	if e := requireMethod(r, "POST"); e != nil {
		return e
	}
	body, e := jsonBody(r, "node_id")
	if e != nil {
		return e
	}
	node := text(body["node_id"])
	if !domain.ValidIdentifier(node) {
		return domain.Err(422, "invalid_request")
	}
	if s.options.ParticipantEnroll == nil {
		if _, e := s.manager.GetJob(r.Context(), actor, id); e != nil {
			return e
		}
		return domain.Err(503, "participant_enrollment_unavailable")
	}
	expected, e := version(r)
	if e != nil {
		return e
	}
	key, e := idempotency(r)
	if e != nil {
		return e
	}
	v, e := s.options.ParticipantEnroll(r.Context(), actor, id, participant, node, expected, key)
	if e != nil {
		return e
	}
	return view(w, 202, v, Prefix+"/jobs/"+url.PathEscape(id)+"/participants/"+url.PathEscape(participant)+"/enrollment")
}
func (s *Server) eventsStream(w http.ResponseWriter, r *http.Request) error {
	if e := requireMethod(r, "GET"); e != nil {
		return e
	}
	actor, e := s.actor(r, false, true)
	if e != nil {
		return e
	}
	event := "invalidated"
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		expired, e := s.readCursor(v, actor.ID)
		if e != nil {
			return e
		}
		if expired {
			event = "reset"
		}
	}
	snapshot, e := s.manager.VisibleRevision(r.Context(), actor.ID)
	if e != nil {
		return e
	}
	token, e := s.issueCursor(actor.ID, snapshot)
	if e != nil {
		return e
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		return errors.New("streaming response unavailable")
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	if _, e = fmt.Fprintf(w, "event: %s\nid: %s\ndata: {\"refetch\":true}\n\n", event, token); e != nil {
		return nil
	}
	flusher.Flush()
	timer := time.NewTicker(s.options.SSEPollInterval)
	defer timer.Stop()
	for {
		select {
		case <-r.Context().Done():
			return nil
		case <-timer.C:
			fresh, e := s.actor(r, false, false)
			if e != nil {
				var d *domain.Error
				if errors.As(e, &d) && (d.Status == 401 || d.Status == 403 || d.Status == 404) {
					_, _ = io.WriteString(w, "event: session_expired\ndata: {\"refetch\":true}\n\n")
					flusher.Flush()
				}
				return nil
			}
			if fresh.ID != actor.ID {
				return nil
			}
			latest, e := s.manager.VisibleRevision(r.Context(), fresh.ID)
			if e != nil {
				return nil
			}
			if latest != snapshot {
				snapshot = latest
				token, e = s.issueCursor(fresh.ID, snapshot)
				if e != nil {
					return nil
				}
				_, e = fmt.Fprintf(w, "event: invalidated\nid: %s\ndata: {\"refetch\":true}\n\n", token)
			} else {
				_, e = io.WriteString(w, ": keepalive\n\n")
			}
			if e != nil {
				return nil
			}
			flusher.Flush()
		}
	}
}

func publicMethods(parts []string) []string {
	if len(parts) == 0 {
		return nil
	}
	switch parts[0] {
	case "catalog":
		if len(parts) == 1 {
			return []string{"GET"}
		}
	case "pools":
		if len(parts) == 1 {
			return []string{"GET"}
		}
		if len(parts) == 2 && parts[1] != "" {
			return []string{"PUT"}
		}
	case "jobs":
		if len(parts) == 1 {
			return []string{"GET", "POST"}
		}
		if len(parts) < 2 || parts[1] == "" {
			return nil
		}
		if len(parts) == 2 {
			return []string{"GET"}
		}
		switch parts[2] {
		case "attempts", "events", "logs":
			if len(parts) == 3 {
				return []string{"GET"}
			}
		case "cancel", "retry", "reconcile", "purge":
			if len(parts) == 3 {
				return []string{"POST"}
			}
		case "members":
			if len(parts) == 3 {
				return []string{"GET"}
			}
			if len(parts) == 4 && parts[3] != "" {
				return []string{"PUT", "DELETE"}
			}
		case "artifacts":
			if len(parts) == 3 || (len(parts) == 4 && parts[3] != "") || (len(parts) == 5 && parts[3] != "" && parts[4] == "download") {
				return []string{"GET"}
			}
		case "participants":
			if len(parts) == 5 && parts[3] != "" {
				if parts[4] == "enroll" {
					return []string{"POST"}
				}
				if parts[4] == "enrollment" {
					return []string{"GET"}
				}
			}
		}
	}
	return nil
}
