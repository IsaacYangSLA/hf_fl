package transfer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

type ProxySettings struct {
	ExchangeEndpoint  string
	GatewayEndpoint   string
	ClientCertificate string
	ClientKey         string
	CAFile            string
	Binding           ExecutionBinding
	ExchangeToken     func(context.Context) (string, error)
	GatewayToken      func(context.Context) (string, error)
	WorkloadIssuer    string
	WorkloadPublicKey string
	ExchangeAudience  string
	GatewayAudience   string
	MaxControlBytes   int64
	MaxPartBytes      int64
	MaxDownloadBytes  int64
	Timeout           time.Duration
	// Client is an injectable transport for tests; leave nil in production.
	Client *http.Client
}

func (s *ProxySettings) defaults() error {
	var e error
	s.ExchangeEndpoint, e = serviceEndpoint(s.ExchangeEndpoint)
	if e != nil {
		return e
	}
	s.GatewayEndpoint, e = serviceEndpoint(s.GatewayEndpoint)
	if e != nil {
		return e
	}
	if e = s.Binding.Validate(); e != nil {
		return e
	}
	if s.ExchangeAudience == "" {
		s.ExchangeAudience = "exchange-workload"
	}
	if s.GatewayAudience == "" {
		s.GatewayAudience = "hf2l-transfer"
	}
	if s.ExchangeAudience == s.GatewayAudience || s.WorkloadIssuer == "" || s.WorkloadPublicKey == "" {
		return errors.New("distinct workload audiences and verification key required")
	}
	if s.ExchangeToken == nil || s.GatewayToken == nil {
		return errors.New("trusted credential providers required")
	}
	if s.ClientCertificate == "" || s.ClientKey == "" || s.CAFile == "" {
		return errors.New("external private mTLS credentials and trust file required")
	}
	data, e := os.ReadFile(s.ClientCertificate)
	if e != nil {
		return e
	}
	cert, e := certFromPEM(data)
	if e != nil {
		return e
	}
	if cert.IsCA || CertificateThumbprint(cert.Raw) != s.Binding.CertificateThumbprint {
		return errors.New("proxy certificate binding mismatch")
	}
	validUsage := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == 2 {
			validUsage = true
		}
	}
	if !validUsage {
		return errors.New("proxy certificate requires client authentication purpose")
	}
	if _, e = tlsConfig(s.CAFile, s.ClientCertificate, s.ClientKey); e != nil {
		return e
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return errors.New("proxy certificate is not current")
	}
	if s.MaxControlBytes == 0 {
		s.MaxControlBytes = 1 << 20
	}
	if s.MaxPartBytes == 0 {
		s.MaxPartBytes = 64 << 20
	}
	if s.MaxDownloadBytes == 0 {
		s.MaxDownloadBytes = 1 << 40
	}
	if s.Timeout == 0 {
		s.Timeout = 300 * time.Second
	}
	if s.MaxControlBytes < 1 || s.MaxPartBytes < 1 || s.MaxDownloadBytes < 1 || s.Timeout <= 0 {
		return errors.New("positive proxy limits required")
	}
	return nil
}

var controls = []struct {
	method string
	path   *regexp.Regexp
}{
	{"GET", regexp.MustCompile("^$")}, {"GET", regexp.MustCompile("^/(membership|members|types)$")},
	{"GET", regexp.MustCompile("^/types/[A-Za-z0-9_.-]+/revisions/[A-Za-z0-9_.-]+$")},
	{"GET", regexp.MustCompile("^/(records|events)$")}, {"POST", regexp.MustCompile("^/records$")},
	{"GET", regexp.MustCompile("^/records/[A-Za-z0-9_-]+$")}, {"PATCH", regexp.MustCompile("^/records/[A-Za-z0-9_-]+$")}, {"DELETE", regexp.MustCompile("^/records/[A-Za-z0-9_-]+$")},
	{"POST", regexp.MustCompile("^/records/[A-Za-z0-9_-]+/publish$")},
	{"GET", regexp.MustCompile("^/refs/main$")}, {"PUT", regexp.MustCompile("^/refs/main$")},
	{"POST", regexp.MustCompile("^/acquisitions$")}, {"GET", regexp.MustCompile("^/acquisitions/[A-Za-z0-9_-]+$")},
	{"POST", regexp.MustCompile("^/acquisitions/[A-Za-z0-9_-]+/(renew|abandon|complete)$")},
	{"POST", regexp.MustCompile("^/records/[A-Za-z0-9_-]+/attachments/[A-Za-z0-9_-]+/(upload|grants|complete)$")},
	{"GET", regexp.MustCompile("^/records/[A-Za-z0-9_-]+/attachments/[A-Za-z0-9_-]+/(parts|download)$")},
}
var putTransfer = regexp.MustCompile("^[A-Za-z0-9_-]+/attachments/[A-Za-z0-9_-]+/parts/[1-9][0-9]{0,3}$")
var getTransfer = regexp.MustCompile("^[A-Za-z0-9_-]+/attachments/[A-Za-z0-9_-]+/content$")

func proxyRoute(binding ExecutionBinding, r *http.Request) (bool, error) {
	if unsafePath(r) {
		return false, domain.Err(404, "operation_not_allowed")
	}
	path := r.URL.Path
	prefix := "/v2/spaces/" + binding.SpaceID
	if path == prefix || strings.HasPrefix(path, prefix+"/") {
		suffix := strings.TrimPrefix(path, prefix)
		for _, allowed := range controls {
			if allowed.method == r.Method && allowed.path.MatchString(suffix) {
				return false, nil
			}
		}
	}
	prefix = "/transfers/v1/spaces/" + binding.SpaceID + "/records/"
	if strings.HasPrefix(path, prefix) {
		suffix := strings.TrimPrefix(path, prefix)
		if r.Method == "PUT" && putTransfer.MatchString(suffix) {
			return true, nil
		}
		if (r.Method == "GET" || r.Method == "HEAD") && getTransfer.MatchString(suffix) {
			return true, nil
		}
	}
	return false, domain.Err(404, "operation_not_allowed")
}

type Proxy struct {
	settings                          ProxySettings
	client                            *http.Client
	exchangeVerifier, gatewayVerifier WorkloadVerifier
	slots                             chan struct{}
}

func NewProxy(settings ProxySettings) (http.Handler, error) {
	if e := settings.defaults(); e != nil {
		return nil, e
	}
	x := WorkloadVerifier{Issuer: settings.WorkloadIssuer, Audience: settings.ExchangeAudience, Scope: "exchange", PublicKey: settings.WorkloadPublicKey}
	y := WorkloadVerifier{Issuer: settings.WorkloadIssuer, Audience: settings.GatewayAudience, Scope: "transfer", PublicKey: settings.WorkloadPublicKey}
	if e := x.Validate(); e != nil {
		return nil, e
	}
	if e := y.Validate(); e != nil {
		return nil, e
	}
	client := settings.Client
	if client == nil {
		var e error
		client, e = newClient(settings.CAFile, settings.ClientCertificate, settings.ClientKey, settings.Timeout)
		if e != nil {
			return nil, e
		}
	}
	return &Proxy{settings, client, x, y, make(chan struct{}, 64)}, nil
}
func (p *Proxy) tokenFor(ctx context.Context, transfer bool) (string, error) {
	provider := p.settings.ExchangeToken
	verifier := &p.exchangeVerifier
	if transfer {
		provider = p.settings.GatewayToken
		verifier = &p.gatewayVerifier
	}
	token, e := provider(ctx)
	if e != nil {
		var d *domain.Error
		if errors.As(e, &d) {
			if d.Status == 401 || d.Status == 403 || d.Status == 404 || d.Status == 410 {
				return "", domain.Err(403, "execution_authority_denied")
			}
			if d.Status == 408 || d.Status == 429 || d.Status >= 500 && d.Status <= 599 || d.Status == 409 && d.Code == "participant_assignment_not_ready" {
				return "", domain.Err(503, "execution_service_unavailable")
			}
		}
		return "", e
	}
	id, e := verifier.Verify(token, p.settings.Binding.CertificateThumbprint)
	if e != nil || id.ExecutionBinding != p.settings.Binding {
		return "", domain.Err(401, "invalid_execution_credential")
	}
	return token, nil
}
func forbiddenCallerHeaders(r *http.Request) bool {
	for name := range r.Header {
		n := strings.ToLower(name)
		if n == "authorization" || n == "proxy-authorization" || n == "cookie" || strings.HasPrefix(n, "x-hf2l-") || n == "x-forwarded-client-cert" || n == "x-forwarded-host" {
			return true
		}
	}
	return false
}
func unsafeControl(value []byte) bool {
	if bytes.Contains(value, []byte(`"url"`)) || bytes.Contains(value, []byte(`"access_key"`)) || bytes.Contains(value, []byte(`"secret_key"`)) {
		return true
	}
	var data any
	d := json.NewDecoder(bytes.NewReader(value))
	d.UseNumber()
	if d.Decode(&data) != nil {
		return false
	}
	var walk func(any) bool
	walk = func(v any) bool {
		switch item := v.(type) {
		case map[string]any:
			for k, x := range item {
				switch strings.ToLower(k) {
				case "url", "access_key", "secret_key":
					return true
				}
				if walk(x) {
					return true
				}
			}
		case []any:
			for _, x := range item {
				if walk(x) {
					return true
				}
			}
		}
		return false
	}
	return walk(data)
}
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		writeError(w, domain.Err(503, "execution_service_unavailable"))
		return
	}
	if forbiddenCallerHeaders(r) {
		writeError(w, domain.Err(400, "caller_credentials_forbidden"))
		return
	}
	transfer, e := proxyRoute(p.settings.Binding, r)
	if e != nil {
		writeError(w, e)
		return
	}
	if transfer && r.URL.RawQuery != "" {
		writeError(w, domain.Err(400, "unexpected_transfer_query"))
		return
	}
	limit := p.settings.MaxControlBytes
	if transfer && r.Method == "PUT" {
		limit = p.settings.MaxPartBytes
	}
	if r.ContentLength < 0 || r.ContentLength > limit || len(r.TransferEncoding) > 0 {
		writeError(w, domain.Err(413, "request_too_large"))
		return
	}
	if transfer && r.Method == "PUT" && r.Header.Get("Content-Length") == "" {
		writeError(w, domain.Err(411, "content_length_required"))
		return
	}
	token, e := p.tokenFor(r.Context(), transfer)
	if e != nil {
		writeError(w, e)
		return
	}
	endpoint := p.settings.ExchangeEndpoint
	if transfer {
		endpoint = p.settings.GatewayEndpoint
	}
	headers := http.Header{}
	copyHeaders(headers, r.Header, safeRequestHeaders)
	headers.Set("Authorization", "Bearer "+token)
	headers.Set("Accept-Encoding", "identity")
	headers.Del("Content-Length")
	var body io.ReadCloser
	if transfer && r.Method == "PUT" {
		body = &checkedReader{source: r.Body, remaining: r.ContentLength, chunk: 65536, check: func() error { _, e := p.tokenFor(r.Context(), true); return e }}
	} else {
		raw, e := readBounded(r.Body, limit)
		if e != nil {
			writeError(w, e)
			return
		}
		if int64(len(raw)) != r.ContentLength {
			writeError(w, domain.Err(400, "content_length_mismatch"))
			return
		}
		body = io.NopCloser(bytes.NewReader(raw))
	}
	upstreamRequest, e := http.NewRequestWithContext(r.Context(), r.Method, endpoint+requestTarget(r), body)
	if e != nil {
		writeError(w, domain.Err(503, "execution_service_unavailable"))
		return
	}
	upstreamRequest.Header = headers
	upstreamRequest.ContentLength = r.ContentLength
	if r.ContentLength == 0 {
		upstreamRequest.Body = http.NoBody
	}
	response, e := p.client.Do(upstreamRequest)
	if e != nil {
		writeError(w, domain.Err(503, "execution_service_unavailable"))
		return
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		writeError(w, domain.Err(502, "redirect_not_allowed"))
		return
	}
	responseLimit := p.settings.MaxControlBytes
	if transfer && (r.Method == "GET" || r.Method == "HEAD") {
		responseLimit = p.settings.MaxDownloadBytes
	}
	if !transfer {
		value, e := readBounded(response.Body, responseLimit)
		if e != nil {
			writeError(w, domain.Err(502, "control_response_too_large"))
			return
		}
		if unsafeControl(value) {
			writeError(w, domain.Err(502, "unsafe_control_descriptor"))
			return
		}
		copyHeaders(w.Header(), response.Header, safeResponseHeaders)
		w.WriteHeader(response.StatusCode)
		if r.Method != "HEAD" {
			_, _ = w.Write(value)
		}
		return
	}
	if value := response.Header.Get("Content-Length"); value != "" {
		n, e := strconv.ParseInt(value, 10, 64)
		if e != nil || n < 0 || n > responseLimit {
			writeError(w, domain.Err(502, "transfer_response_too_large"))
			return
		}
	}
	copyHeaders(w.Header(), response.Header, safeResponseHeaders)
	w.WriteHeader(response.StatusCode)
	if r.Method == "HEAD" {
		return
	}
	buf := make([]byte, 65536)
	var total int64
	for {
		if _, e = p.tokenFor(r.Context(), true); e != nil {
			return
		}
		n, e := response.Body.Read(buf)
		if n > 0 {
			if _, err := p.tokenFor(r.Context(), true); err != nil {
				return
			}
			total += int64(n)
			if total > responseLimit {
				return
			}
			if _, e = w.Write(buf[:n]); e != nil {
				return
			}
			flush(w)
		}
		if e != nil {
			return
		}
	}
}

type EdgeSettings struct {
	ClientCertificate string
	ClientKey         string
	BackendEndpoint   string
	BackendSecret     string
	CAFile            string
	MaxControlBytes   int64
	Timeout           time.Duration
	Client            *http.Client
	Clock             func() time.Time
}
type Edge struct {
	settings EdgeSettings
	client   *http.Client
}

func NewEdge(settings EdgeSettings) (http.Handler, error) {
	endpoint, e := serviceEndpoint(settings.BackendEndpoint)
	if e != nil {
		return nil, e
	}
	settings.BackendEndpoint = endpoint
	if len([]byte(settings.BackendSecret)) < 32 {
		return nil, errors.New("private backend secret must contain at least 32 bytes")
	}
	if settings.MaxControlBytes == 0 {
		settings.MaxControlBytes = 1 << 20
	}
	if settings.MaxControlBytes < 1 {
		return nil, errors.New("positive control limit required")
	}
	if settings.Timeout == 0 {
		settings.Timeout = 300 * time.Second
	}
	if settings.Clock == nil {
		settings.Clock = time.Now
	}
	if (settings.ClientCertificate == "") != (settings.ClientKey == "") {
		return nil, errors.New("backend client certificate and private key must be configured together")
	}
	client := settings.Client
	if client != nil && settings.ClientCertificate != "" {
		if _, e = tlsConfig(settings.CAFile, settings.ClientCertificate, settings.ClientKey); e != nil {
			return nil, e
		}
	}

	if client == nil {
		client, e = newClient(settings.CAFile, settings.ClientCertificate, settings.ClientKey, settings.Timeout)
		if e != nil {
			return nil, e
		}
	}
	return &Edge{settings, client}, nil
}
func (e *Edge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	thumb, err := verifiedThumbprint(r)
	if err != nil {
		writeError(w, err)
		return
	}
	switch r.Method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE":
	default:
		writeError(w, domain.Err(405, "method_not_allowed"))
		return
	}
	if unsafePath(r) || !strings.HasPrefix(r.URL.Path, "/v2/spaces/") {
		writeError(w, domain.Err(404, "operation_not_allowed"))
		return
	}
	if r.ContentLength < 0 || r.ContentLength > e.settings.MaxControlBytes || len(r.TransferEncoding) > 0 {
		writeError(w, domain.Err(413, "request_too_large"))
		return
	}
	raw, err := readBounded(r.Body, e.settings.MaxControlBytes)
	if err != nil {
		writeError(w, err)
		return
	}
	if int64(len(raw)) != r.ContentLength {
		writeError(w, domain.Err(400, "content_length_mismatch"))
		return
	}
	target := requestTarget(r)
	headers := http.Header{}
	copyHeaders(headers, r.Header, safeRequestHeaders)
	authorization := r.Header.Get("Authorization")
	headers.Set("Authorization", authorization)
	headers.Set("Accept-Encoding", "identity")
	assertion, err := BackendAssertionHeaders(e.settings.BackendSecret, r.Method, target, authorization, thumb, e.settings.Clock())
	if err != nil {
		writeError(w, domain.Err(503, "backend_unavailable"))
		return
	}
	for k, v := range assertion {
		headers[k] = v
	}
	upstream, err := http.NewRequestWithContext(r.Context(), r.Method, e.settings.BackendEndpoint+target, bytes.NewReader(raw))
	if err != nil {
		writeError(w, domain.Err(503, "backend_unavailable"))
		return
	}
	upstream.Header = headers
	response, err := e.client.Do(upstream)
	if err != nil {
		writeError(w, domain.Err(503, "backend_unavailable"))
		return
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		writeError(w, domain.Err(502, "unsafe_backend_response"))
		return
	}
	value, err := readBounded(response.Body, e.settings.MaxControlBytes)
	if err != nil {
		writeError(w, domain.Err(502, "unsafe_backend_response"))
		return
	}
	copyHeaders(w.Header(), response.Header, map[string]bool{"content-type": true, "etag": true, "retry-after": true})
	w.WriteHeader(response.StatusCode)
	if r.Method != "HEAD" {
		_, _ = w.Write(value)
	}
}

// Close releases owned outbound connections after the serving HTTP listener is
// stopped. It does not terminate or release the associated training execution.
func (p *Proxy) Close() error { p.client.CloseIdleConnections(); return nil }
func (e *Edge) Close() error  { e.client.CloseIdleConnections(); return nil }
