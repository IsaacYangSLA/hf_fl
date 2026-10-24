package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/auth"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/manager"
)

const csp = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

var requestIDPattern = regexp.MustCompile("^[A-Za-z0-9_.-]{1,64}$")
var idempotencyPattern = regexp.MustCompile("^[A-Za-z0-9_.:-]{1,128}$")
var etagPattern = regexp.MustCompile(`^"([1-9][0-9]*)"$`)
var shaPattern = regexp.MustCompile("^[a-f0-9]{64}$")
var thumbPattern = regexp.MustCompile("^[A-Za-z0-9_-]{43}$")
var states = map[string]bool{"QUEUED": true, "PROVISIONING": true, "STARTING": true, "RUNNING": true, "RECONCILING": true, "NEEDS_ATTENTION": true, "CANCELLING": true, "SUCCEEDED": true, "FAILED": true, "CANCELLED": true}

type Server struct {
	manager *manager.Manager
	auth    *auth.Service
	options Options
	static  http.Handler
}
type requestIDKey struct{}

func New(m *manager.Manager, a *auth.Service, opts Options) (*Server, error) {
	if opts.PublicOnly && opts.PrivateOnly {
		return nil, errors.New("public and private ingress modes are mutually exclusive")
	}
	if m == nil || a == nil {
		return nil, errors.New("manager and authentication services are required")
	}
	if len(opts.CursorSecret) == 0 {
		opts.CursorSecret = append([]byte(nil), m.CursorSecret...)
	}
	if len(opts.CursorSecret) < 32 {
		return nil, errors.New("persistent event cursor secret must contain at least 32 bytes")
	}
	if opts.MaxBodyBytes == 0 {
		opts.MaxBodyBytes = 1048576
	}
	if opts.MaxBodyBytes < 1 || opts.MaxBodyBytes > 1<<30 {
		return nil, errors.New("invalid request body limit")
	}
	if opts.SSEPollInterval == 0 {
		opts.SSEPollInterval = 10 * time.Second
	}
	if opts.SSEPollInterval < 50*time.Millisecond {
		opts.SSEPollInterval = 50 * time.Millisecond
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	s := &Server{manager: m, auth: a, options: opts}
	if opts.Dashboard != nil {
		s.static = http.FileServer(http.FS(opts.Dashboard))
	}
	return s, nil
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	if !requestIDPattern.MatchString(requestID) {
		requestID = domain.NewID()
	}
	r = r.WithContext(context.WithValue(r.Context(), requestIDKey{}, requestID))
	for k, v := range map[string]string{"Content-Security-Policy": csp, "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store", "Permissions-Policy": "camera=(), microphone=(), geolocation=()", "X-Request-ID": requestID} {
		w.Header().Set(k, v)
	}
	if r.TLS == nil && !(s.options.AllowLocalHTTP && isLoopback(r.RemoteAddr)) {
		s.writeError(w, r, domain.Err(426, "https_required"))
		return
	}
	if raw := r.Header.Get("Content-Length"); raw != "" {
		n, e := strconv.ParseInt(raw, 10, 64)
		if e != nil || n < 0 {
			s.writeError(w, r, domain.Err(400, "invalid_content_length"))
			return
		}
		if n > s.options.MaxBodyBytes {
			s.writeError(w, r, domain.Err(413, "request_too_large"))
			return
		}
	}
	if r.ContentLength < -1 {
		s.writeError(w, r, domain.Err(400, "invalid_content_length"))
		return
	}
	if r.ContentLength > s.options.MaxBodyBytes {
		s.writeError(w, r, domain.Err(413, "request_too_large"))
		return
	}
	if r.Body != nil {
		data, e := io.ReadAll(io.LimitReader(r.Body, s.options.MaxBodyBytes+1))
		_ = r.Body.Close()
		if e != nil {
			s.writeError(w, r, domain.Err(400, "invalid_request"))
			return
		}
		if int64(len(data)) > s.options.MaxBodyBytes {
			s.writeError(w, r, domain.Err(413, "request_too_large"))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(data))
	}
	for _, name := range []string{"Authorization", "Origin", "X-CSRF-Token", "If-Match", "Idempotency-Key"} {
		if len(r.Header.Values(name)) > 1 {
			s.writeError(w, r, domain.Err(400, "invalid_request"))
			return
		}
	}
	if err := s.route(w, r); err != nil {
		s.writeError(w, r, err)
	}
}
func isLoopback(address string) bool {
	host, _, e := net.SplitHostPort(address)
	if e != nil {
		host = address
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}
func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	status, code, detail := 500, "internal_error", any("")
	var d *domain.Error
	if errors.As(err, &d) {
		status, code = d.Status, d.Code
		if d.Details != nil {
			detail = d.Details
		}
		for k, v := range d.Headers {
			if strings.EqualFold(k, "WWW-Authenticate") || strings.EqualFold(k, "Retry-After") {
				w.Header().Set(k, v)
			}
		}
	}
	if status < 400 || status > 599 {
		status = 500
		code = "internal_error"
		detail = ""
	}
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "detail": detail, "request_id": r.Context().Value(requestIDKey{})}})
}
func writeJSON(w http.ResponseWriter, status int, v any) error {
	data, e := json.Marshal(v)
	if e != nil {
		return e
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
	return nil
}
func view(w http.ResponseWriter, status int, v map[string]any, location string) error {
	if n, ok := integer(v["version"]); ok {
		w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(n, 10)))
	}
	if location != "" {
		w.Header().Set("Location", location)
	}
	return writeJSON(w, status, v)
}
func cookie(r *http.Request, name string) (string, error) {
	value := ""
	found := false
	for _, c := range r.Cookies() {
		if c.Name == name {
			if found {
				return "", domain.Err(401, "ambiguous_authentication")
			}
			value = c.Value
			found = true
		}
	}
	return value, nil
}
func (s *Server) actor(r *http.Request, mutation bool, touch bool) (auth.Principal, error) {
	token, e := cookie(r, auth.SessionCookie)
	if e != nil {
		return auth.Principal{}, e
	}
	a, e := s.auth.AuthenticateRequest(r.Context(), r.Header.Get("Authorization"), token, touch)
	if e != nil {
		return a, e
	}
	if mutation && token != "" {
		e = s.auth.RequireCSRF(r.Context(), token, r.Header.Get("X-CSRF-Token"), r.Header.Get("Origin"))
	}
	return a, e
}
func requireMethod(r *http.Request, want string) error {
	if r.Method != want {
		return domain.Err(405, "http_error")
	}
	return nil
}
func idempotency(r *http.Request) (string, error) {
	v := r.Header.Get("Idempotency-Key")
	if v == "" {
		return "", domain.Err(400, "idempotency_key_required")
	}
	if !idempotencyPattern.MatchString(v) {
		return "", domain.Err(400, "invalid_idempotency_key")
	}
	return v, nil
}
func version(r *http.Request) (int64, error) {
	v := r.Header.Get("If-Match")
	if v == "" {
		return 0, domain.Err(428, "if_match_required")
	}
	m := etagPattern.FindStringSubmatch(v)
	if m == nil {
		return 0, domain.Err(400, "invalid_if_match")
	}
	n, e := strconv.ParseInt(m[1], 10, 64)
	if e != nil {
		return 0, domain.Err(400, "invalid_if_match")
	}
	return n, nil
}
func queryInt(q url.Values, key string, def int, min, max int64) (int, error) {
	raw := q.Get(key)
	if raw == "" {
		if q.Has(key) {
			return 0, domain.Err(422, "invalid_request")
		}
		return def, nil
	}
	n, e := strconv.ParseInt(raw, 10, 64)
	if e != nil || n < min || n > max {
		return 0, domain.Err(422, "invalid_request")
	}
	return int(n), nil
}
func queryText(q url.Values, key string, max int) (string, error) {
	v := q.Get(key)
	if utf8.RuneCountInString(v) > max {
		return "", domain.Err(422, "invalid_request")
	}
	return v, nil
}
func integer(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int64:
		return x, true
	case int32:
		return int64(x), true
	case json.Number:
		n, e := x.Int64()
		return n, e == nil
	}
	return 0, false
}
func text(v any) string            { x, _ := v.(string); return x }
func boolValue(v any) (bool, bool) { x, ok := v.(bool); return x, ok }
func jsonBody(r *http.Request, allowed ...string) (map[string]any, error) {
	if !jsonMediaType(r) {
		return nil, domain.Err(422, "invalid_request")
	}
	raw, e := io.ReadAll(r.Body)
	if e != nil {
		return nil, domain.Err(422, "invalid_request")
	}
	value, e := decodeObject(raw)
	if e != nil {
		return nil, domain.Err(422, "invalid_request")
	}
	known := map[string]bool{}
	for _, k := range allowed {
		known[k] = true
	}
	for k := range value {
		if !known[k] {
			return nil, domain.Err(422, "invalid_request")
		}
	}
	return value, nil
}
func decodeObject(raw []byte) (map[string]any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("invalid JSON encoding")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, e := readValue(d, 0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errors.New("multiple JSON values")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("JSON object required")
	}
	return m, nil
}
func readValue(d *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, errors.New("JSON nesting too deep")
	}
	t, e := d.Token()
	if e != nil {
		return nil, e
	}
	delimiter, ok := t.(json.Delim)
	if !ok {
		return t, nil
	}
	switch delimiter {
	case '{':
		m := map[string]any{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return nil, e
			}
			key, ok := k.(string)
			if !ok {
				return nil, errors.New("invalid object")
			}
			if _, exists := m[key]; exists {
				return nil, errors.New("duplicate JSON key")
			}
			v, e := readValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			m[key] = v
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return nil, errors.New("invalid object")
		}
		return m, nil
	case '[':
		a := []any{}
		for d.More() {
			v, e := readValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			a = append(a, v)
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return nil, errors.New("invalid array")
		}
		return a, nil
	}
	return nil, errors.New("invalid JSON value")
}
func (s *Server) issueCursor(actor, snapshot string) (string, error) {
	nonce := make([]byte, 12)
	if _, e := rand.Read(nonce); e != nil {
		return "", e
	}
	raw, e := domain.CanonicalJSON(map[string]any{"p": actor, "t": s.options.Clock().Unix(), "n": hex.EncodeToString(nonce), "s": snapshot})
	if e != nil {
		return "", e
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, s.options.CursorSecret)
	mac.Write([]byte(encoded))
	return encoded + "." + hex.EncodeToString(mac.Sum(nil)), nil
}
func (s *Server) readCursor(value, actor string) (expired bool, err error) {
	invalid := func() (bool, error) { return false, domain.Err(400, "invalid_event_cursor") }
	if len(value) > 2048 {
		return invalid()
	}
	pieces := strings.Split(value, ".")
	if len(pieces) != 2 {
		return invalid()
	}
	signature, e := hex.DecodeString(pieces[1])
	if e != nil {
		return invalid()
	}
	mac := hmac.New(sha256.New, s.options.CursorSecret)
	mac.Write([]byte(pieces[0]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return invalid()
	}
	raw, e := base64.RawURLEncoding.Strict().DecodeString(pieces[0])
	if e != nil {
		return invalid()
	}
	v, e := decodeObject(raw)
	if e != nil || text(v["p"]) != actor {
		return invalid()
	}
	stamp, ok := integer(v["t"])
	if !ok {
		return invalid()
	}
	age := s.options.Clock().Unix() - stamp
	if age < -30 {
		return invalid()
	}
	return age > 3600, nil
}

func jsonMediaType(r *http.Request) bool {
	value := r.Header.Get("Content-Type")
	if value == "" {
		return true
	}
	media, _, err := mime.ParseMediaType(value)
	return err == nil && (media == "application/json" || (strings.HasPrefix(media, "application/") && strings.HasSuffix(media, "+json")))
}
