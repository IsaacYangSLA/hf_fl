package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"math"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/auth"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/service"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/storage"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/transfers"
)

type Options struct {
	ManagedIngress bool
	MaxBodyBytes   int64
	AllowLocalHTTP bool
	DocsEnabled    bool
	AuthSettings   config.AuthSettings
}
type server struct {
	core          *service.Service
	raw           *transfers.Service
	managed       *transfers.ManagedService
	authenticator *auth.Authenticator
	options       Options
	contract      *compiledContract
}

// New composes an ordinary or managed listener without contacting dependencies.
// The private transfer backend is deliberately not mounted here.
func New(core *service.Service, raw *transfers.Service, a *auth.Authenticator, options Options) (http.Handler, error) {
	if core == nil || core.DB == nil || raw == nil || raw.Storage == nil || a == nil {
		return nil, errors.New("Exchange HTTP collaborators are required")
	}
	if options.MaxBodyBytes == 0 {
		options.MaxBodyBytes = config.DefaultSettings().MaxBodyBytes
	}
	if options.MaxBodyBytes < 1 || options.MaxBodyBytes == math.MaxInt64 {
		return nil, errors.New("invalid HTTP body limit")
	}
	if options.ManagedIngress {
		if !options.AuthSettings.WorkloadsEnabled() {
			return nil, errors.New("managed ingress requires workload identity")
		}
		if err := options.AuthSettings.Validate(); err != nil {
			return nil, err
		}
	}
	c, err := publicContract()
	if err != nil {
		return nil, err
	}
	return &server{core: core, raw: raw, managed: transfers.NewManaged(raw), authenticator: a, options: options, contract: c}, nil
}

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get("X-Request-ID")
	if !requestIDPattern.MatchString(id) {
		id = domain.NewID()
	}
	w.Header().Set("X-Request-ID", id)
	defer func() {
		if recover() != nil {
			s.writeFailure(w, id, 500, "internal_error", "", nil)
		}
	}()
	if r.TLS == nil && !(s.options.AllowLocalHTTP && loopback(r.RemoteAddr)) {
		s.writeFailure(w, id, 426, "https_required", "", nil)
		return
	}
	if raw := r.Header.Get("Content-Length"); raw != "" {
		n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil || n < 0 {
			s.writeFailure(w, id, 400, "invalid_content_length", "", nil)
			return
		}
		if n > s.options.MaxBodyBytes {
			s.writeFailure(w, id, 413, "request_too_large", "", nil)
			return
		}
	}
	if r.ContentLength > s.options.MaxBodyBytes {
		s.writeFailure(w, id, 413, "request_too_large", "", nil)
		return
	}
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, s.options.MaxBodyBytes+1))
		_ = r.Body.Close()
		if err != nil {
			if r.Context().Err() != nil {
				return
			}
			s.writeFailure(w, id, 400, "invalid_request", "", nil)
			return
		}
	}
	if int64(len(body)) > s.options.MaxBodyBytes {
		s.writeFailure(w, id, 413, "request_too_large", "", nil)
		return
	}
	s.dispatch(w, r, id, body)
}
func loopback(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}
func matchPath(template, path string) (map[string]string, bool) {
	expected, actual := strings.Split(template, "/"), strings.Split(path, "/")
	if len(expected) != len(actual) {
		return nil, false
	}
	values := map[string]string{}
	for i, part := range expected {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			if actual[i] == "" {
				return nil, false
			}
			values[part[1:len(part)-1]] = actual[i]
		} else if part != actual[i] {
			return nil, false
		}
	}
	return values, true
}
func findRoute(method, path string) (routeSpec, map[string]string, string, bool) {
	firstMethod := ""
	for _, spec := range routeSpecs {
		values, ok := matchPath(spec.path, path)
		if !ok {
			continue
		}
		if firstMethod == "" {
			firstMethod = spec.method
		}
		if spec.method == method {
			return spec, values, "", true
		}
	}
	return routeSpec{}, nil, firstMethod, false
}
func (s *server) dispatch(w http.ResponseWriter, r *http.Request, id string, raw []byte) {
	if r.URL.Path == "/health" && r.Method == "GET" {
		writeJSON(w, 200, object{"status": "alive"})
		return
	}
	if r.URL.Path == "/ready" && r.Method == "GET" {
		if err := s.core.DB.Check(r.Context()); err != nil {
			s.writeFailure(w, id, 503, "not_ready", "not_ready", map[string]string{"Retry-After": "3"})
			return
		}
		if err := s.raw.Storage.Check(r.Context()); err != nil {
			s.writeFailure(w, id, 503, "not_ready", "not_ready", map[string]string{"Retry-After": "3"})
			return
		}
		writeJSON(w, 200, object{"status": "ready", "api_version": 2})
		return
	}
	if s.options.DocsEnabled && r.Method == "GET" {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			_, _ = w.Write(openAPIData)
			return
		}
		if r.URL.Path == "/docs" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(200)
			_, _ = io.WriteString(w, "<!doctype html><html><head><meta charset=\"utf-8\"><title>Exchange API</title></head><body><h1>Exchange API v2</h1><p><a href=\"/openapi.json\">OpenAPI contract</a></p><ul>")
			for _, route := range routeSpecs {
				_, _ = fmt.Fprintf(w, "<li><code>%s %s</code></li>", route.method, html.EscapeString(route.path))
			}
			_, _ = io.WriteString(w, "</ul></body></html>")
			return
		}
	}
	spec, vars, allow, found := findRoute(r.Method, r.URL.Path)
	if !found {
		if allow != "" {
			s.writeFailure(w, id, 405, "http_error", "", map[string]string{"Allow": allow})
			return
		}
		// Starlette's slash redirect is 307 and preserves methods and query strings.
		other := strings.TrimSuffix(r.URL.Path, "/")
		if other == r.URL.Path {
			other += "/"
		}
		if _, _, _, ok := findRoute(r.Method, other); ok {
			target := *r.URL
			target.Path = other
			target.RawPath = ""
			if target.Scheme == "" {
				target.Scheme = "https"
				if r.TLS == nil {
					target.Scheme = "http"
				}
			}
			if target.Host == "" {
				target.Host = r.Host
			}
			w.Header().Set("Location", target.String())
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		if r.URL.Path == "/health" || r.URL.Path == "/ready" || s.options.DocsEnabled && (r.URL.Path == "/docs" || r.URL.Path == "/openapi.json") {
			s.writeFailure(w, id, 405, "http_error", "", map[string]string{"Allow": "GET"})
			return
		}
		s.writeFailure(w, id, 404, "not_found", "", nil)
		return
	}
	var decoded any
	if schema := s.contract.bodySchema(spec); schema != nil {
		value, location := decodeBody(raw, r.Header.Get("Content-Type"))
		if location != "" {
			s.writeFailure(w, id, 422, "invalid_request", location, nil)
			return
		}
		decoded = value
	}
	authorization := r.Header.Get("Authorization")
	if headerCount(r.Header, "Authorization") > 1 {
		s.writeError(w, id, &domain.Error{Status: 401, Code: "invalid_access_token", Detail: "invalid_access_token", Headers: map[string]string{"WWW-Authenticate": "Bearer"}})
		return
	}
	thumb := ""
	if s.options.ManagedIngress {
		target := r.URL.Path
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		var err error
		thumb, err = auth.VerifiedBackendThumbprint(s.options.AuthSettings, r.Method, target, authorization, r.Header, time.Now())
		if err != nil {
			s.writeError(w, id, err)
			return
		}
	}
	p, err := s.authenticator.Authenticate(r.Context(), authorization, s.options.ManagedIngress, thumb)
	if err != nil {
		s.writeError(w, id, err)
		return
	}
	if err = s.core.DB.CheckRevision(r.Context()); err != nil {
		var failure *domain.Error
		if errors.As(err, &failure) {
			copy := *failure
			copy.Status = 503
			copy.Headers = map[string]string{"Retry-After": "3"}
			s.writeError(w, id, &copy)
		} else {
			s.writeFailure(w, id, 503, "database_unavailable", "database_unavailable", map[string]string{"Retry-After": "3"})
		}
		return
	}
	d, problems, err := s.callData(r, spec, vars, decoded)
	if err != nil {
		s.writeError(w, id, err)
		return
	}
	if len(problems) > 0 {
		s.writeFailure(w, id, 422, "invalid_request", strings.Join(problems, "; "), nil)
		return
	}
	out, err := s.invoke(r.Context(), p, spec, d)
	if err != nil {
		s.writeError(w, id, err)
		return
	}
	if spec.etag != "" {
		w.Header().Set("ETag", `"`+fmt.Sprint(out[spec.etag])+`"`)
	}
	writeJSON(w, statusFor(s.contract, spec), out)
}
func headerCount(headers http.Header, name string) int {
	n := 0
	for key, values := range headers {
		if strings.EqualFold(key, name) {
			n += len(values)
		}
	}
	return n
}
func decodeBody(raw []byte, contentType string) (any, string) {
	if len(raw) == 0 {
		return nil, ""
	}
	if contentType != "" {
		media, _, err := mime.ParseMediaType(contentType)
		if err != nil || !(media == "application/json" || strings.HasPrefix(media, "application/") && strings.HasSuffix(media, "+json")) {
			return raw, ""
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		offset := len(raw)
		var syntax *json.SyntaxError
		if errors.As(err, &syntax) {
			offset = int(syntax.Offset) - 1
		}
		if offset < 0 {
			offset = 0
		}
		if offset > len(raw) {
			offset = len(raw)
		}
		return nil, "body." + strconv.Itoa(utf8.RuneCount(raw[:offset]))
	}
	offset := int(dec.InputOffset())
	for offset < len(raw) && strings.ContainsRune(" \t\r\n", rune(raw[offset])) {
		offset++
	}
	if offset != len(raw) {
		return nil, "body." + strconv.Itoa(utf8.RuneCount(raw[:offset]))
	}
	if _, err := domain.DecodeJSON(raw); err != nil {
		return nil, "body"
	}
	return value, ""
}
func (s *server) callData(r *http.Request, spec routeSpec, vars map[string]string, value any) (callData, []string, error) {
	d := callData{vars: vars}
	problems := []string{}
	operation := s.contract.operations[spec.method+" "+spec.path]
	values := map[string]any{}
	for _, raw := range anySlice(operation["parameters"]) {
		param, _ := raw.(map[string]any)
		name, _ := param["name"].(string)
		where, _ := param["in"].(string)
		schema, _ := param["schema"].(map[string]any)
		location := where + "." + name
		var supplied any
		present := false
		switch where {
		case "path":
			supplied, present = vars[name]
		case "query":
			items, ok := r.URL.Query()[name]
			present = ok && len(items) > 0
			if present {
				supplied = items[len(items)-1]
			}
		case "header":
			if strings.EqualFold(name, "authorization") {
				continue
			}
			present = headerCount(r.Header, name) > 0
			if present {
				supplied = r.Header.Get(name)
			}
		default:
			return d, nil, domain.Err(500, "internal_error")
		}
		if !present {
			if def, ok := schema["default"]; ok {
				supplied = def
			} else if required, _ := param["required"].(bool); required {
				problems = append(problems, location)
				continue
			} else {
				values[name] = nil
				continue
			}
		}
		if text, ok := supplied.(string); ok && allowsInteger(schema) {
			integer, ok := queryInteger(text)
			if !ok {
				problems = append(problems, location)
				continue
			}
			supplied = json.Number(integer.String())
		}
		parsed, more := s.contract.validate(schema, supplied, location)
		problems = append(problems, more...)
		values[name] = parsed
	}
	if s.contract.bodySchema(spec) != nil {
		var more []string
		d.body, more = s.contract.validateBody(spec, value)
		problems = append(problems, more...)
	}
	if len(problems) > 0 {
		return d, problems, nil
	}
	if key, ok := values["idempotency-key"].(string); ok {
		d.key = key
	}
	if spec.action == "records" {
		d.kind, _ = values["kind"].(string)
		d.after, _ = values["after"].(string)
		d.state, _ = values["state"].(string)
	}
	if spec.action == "records" || spec.action == "events" {
		d.limit, _ = domain.Int64(values["limit"])
	}
	if spec.action == "events" {
		var ok bool
		d.eventAfter, ok = domain.Int64(values["after"])
		if !ok {
			return d, nil, domain.Err(500, "internal_error")
		}
	}
	if spec.action == "get_type" {
		var ok bool
		d.revision, ok = domain.Int64(values["revision"])
		if !ok {
			return d, nil, domain.Err(500, "internal_error")
		}
	}
	if spec.action == "patch_record" || spec.action == "put_reference" {
		expected, err := precondition(r.Header, spec.action == "put_reference")
		if err != nil {
			return d, nil, err
		}
		if spec.action == "patch_record" {
			n, ok := pythonInteger(expected)
			if !ok {
				return d, nil, domain.Err(400, "invalid_precondition")
			}
			expected = n.String()
		}
		d.precondition = expected
	}
	return d, nil, nil
}
func allowsInteger(schema object) bool {
	if schema["type"] == "integer" {
		return true
	}
	for _, raw := range anySlice(schema["anyOf"]) {
		if child, ok := raw.(map[string]any); ok && allowsInteger(child) {
			return true
		}
	}
	return false
}

func lastQuery(q url.Values, key, fallback string) string {
	if values, ok := q[key]; ok && len(values) > 0 {
		return values[len(values)-1]
	}
	return fallback
}

var queryIntegerPattern = regexp.MustCompile(`^[+-]?[0-9](?:_?[0-9])*(?:\.0+)?$`)

func queryInteger(raw string) (*big.Int, bool) {
	raw = strings.TrimSpace(raw)
	if !queryIntegerPattern.MatchString(raw) {
		return nil, false
	}
	if i := strings.IndexByte(raw, '.'); i >= 0 {
		raw = raw[:i]
	}
	return new(big.Int).SetString(strings.ReplaceAll(raw, "_", ""), 10)
}

var pythonIntegerPattern = regexp.MustCompile(`^[+-]?[0-9](?:_?[0-9])*$`)

func pythonInteger(raw string) (*big.Int, bool) {
	raw = strings.TrimSpace(raw)
	if !pythonIntegerPattern.MatchString(raw) {
		return nil, false
	}
	return new(big.Int).SetString(strings.ReplaceAll(raw, "_", ""), 10)
}
func precondition(headers http.Header, includeNone bool) (string, error) {
	matchPresent := headerCount(headers, "If-Match") > 0
	nonePresent := includeNone && headerCount(headers, "If-None-Match") > 0
	if matchPresent && nonePresent {
		return "", domain.Err(400, "ambiguous_precondition")
	}
	if nonePresent {
		if headers.Get("If-None-Match") != "*" {
			return "", domain.Err(400, "invalid_precondition")
		}
		return "*", nil
	}
	if !matchPresent {
		return "", domain.Err(428, "precondition_required")
	}
	value := strings.TrimSpace(headers.Get("If-Match"))
	if strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) && len(value) >= 2 {
		value = value[1 : len(value)-1]
	}
	if value == "" || value == "*" || strings.HasPrefix(value, "W/") || strings.ContainsAny(value, "\",\r\n") {
		return "", domain.Err(400, "invalid_precondition")
	}
	return value, nil
}
func (s *server) writeError(w http.ResponseWriter, id string, err error) {
	var failure *domain.Error
	if errors.As(err, &failure) {
		s.writeFailure(w, id, failure.Status, failure.Code, failure.Detail, failure.Headers)
		return
	}
	var provider *storage.StorageFailure
	if errors.As(err, &provider) {
		failure := provider
		status := 409
		headers := map[string]string{}
		if failure.Retryable {
			status = 503
			headers["Retry-After"] = "3"
		}
		s.writeFailure(w, id, status, failure.Code, "", headers)
		return
	}
	s.writeFailure(w, id, 500, "internal_error", "", nil)
}
func (s *server) writeFailure(w http.ResponseWriter, id string, status int, code, detail string, headers map[string]string) {
	for key, value := range headers {
		w.Header().Set(key, value)
	}
	w.Header().Set("X-Request-ID", id)
	writeJSON(w, status, object{"error": object{"code": code, "detail": detail, "request_id": id}})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		// Domain responses are JSON-safe. An invalid internal value must not leak
		// partial data or its formatting error to callers.
		status = 500
		buf.Reset()
		_ = json.NewEncoder(&buf).Encode(object{"error": object{"code": "internal_error", "detail": "", "request_id": w.Header().Get("X-Request-ID")}})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}
