// Package exchange provides fixed-origin authenticated Exchange control-plane access.
// It never falls back to a Python manager or invokes a credential-bearing shell.
package exchange

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/certificates"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

type Config struct {
	Endpoint, Token, TokenFile, CAFile, CertificateFile, KeyFile string
	CAPEM                                                        []byte
	TokenProvider                                                func(context.Context) (string, error)
	Retries                                                      int
	Timeout                                                      time.Duration
	AllowLocalHTTP                                               bool
	MaxResponseBytes                                             int64
	Sleep                                                        func(context.Context, time.Duration) error
}
type Client struct {
	endpoint    string
	token       func(context.Context) (string, error)
	refreshable bool
	retries     int
	timeout     time.Duration
	maxResponse int64
	http        *http.Client
	sleep       func(context.Context, time.Duration) error
}

func (c *Client) String() string   { return "<ExchangeClient fixed authenticated origin>" }
func (c *Client) Endpoint() string { return c.endpoint }
func ServiceEndpoint(value string, allowLocalHTTP bool) (string, error) {
	u, e := url.Parse(value)
	if e != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.Path != "" && u.Path != "/" || u.RawPath != "" {
		return "", domain.Err(422, "invalid_service_endpoint")
	}
	if u.Scheme != "https" {
		host := u.Hostname()
		local := host == "localhost" || host == "127.0.0.1" || host == "::1"
		if !allowLocalHTTP || u.Scheme != "http" || !local {
			return "", domain.Err(422, "invalid_service_endpoint")
		}
	}
	if u.Port() != "" {
		n, e := strconv.Atoi(u.Port())
		if e != nil || n < 1 || n > 65535 {
			return "", domain.Err(422, "invalid_service_endpoint")
		}
	}
	return strings.TrimSuffix(value, "/"), nil
}
func tokenValue(token string) (string, error) {
	if token == "" || len(token) > 16384 {
		return "", domain.Err(503, "credential_unavailable")
	}
	for _, r := range token {
		if unicode.IsSpace(r) || r < 33 || r == 127 {
			return "", domain.Err(503, "credential_unavailable")
		}
	}
	return token, nil
}

// FileTokenProvider rereads an atomically replaced private token on every request.
// Linux descriptor-relative reads reject links, unsafe owners/modes and mutation.
func FileTokenProvider(path string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		b, e := certificates.ReadPEMFile(path, true)
		if e != nil {
			return "", domain.Err(503, "credential_unavailable")
		}
		return tokenValue(strings.TrimSpace(string(b)))
	}
}
func New(cfg Config) (*Client, error) {
	endpoint, e := ServiceEndpoint(cfg.Endpoint, cfg.AllowLocalHTTP)
	if e != nil {
		return nil, e
	}
	credentials := 0
	if cfg.Token != "" {
		credentials++
	}
	if cfg.TokenFile != "" {
		credentials++
	}
	if cfg.TokenProvider != nil {
		credentials++
	}
	if credentials != 1 {
		return nil, domain.Err(422, "exactly_one_exchange_credential_required")
	}
	provider := cfg.TokenProvider
	refreshable := true
	if cfg.TokenFile != "" {
		provider = FileTokenProvider(cfg.TokenFile)
	}
	if cfg.Token != "" {
		token, e := tokenValue(cfg.Token)
		if e != nil {
			return nil, e
		}
		provider = func(context.Context) (string, error) { return token, nil }
		refreshable = false
	}
	retries := cfg.Retries
	if retries == 0 {
		retries = 3
	}
	if retries < 1 || retries > 20 {
		return nil, domain.Err(422, "invalid_retry_limit")
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	if timeout <= 0 || timeout > time.Hour {
		return nil, domain.Err(422, "invalid_timeout")
	}
	maximum := cfg.MaxResponseBytes
	if maximum == 0 {
		maximum = 64 << 20
	}
	if maximum < 1 || maximum > 1<<30 {
		return nil, domain.Err(422, "invalid_response_limit")
	}
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if cfg.CAFile != "" && len(cfg.CAPEM) > 0 {
		return nil, domain.Err(422, "ambiguous_service_trust")
	}
	ca := cfg.CAPEM
	if cfg.CAFile != "" {
		ca, e = certificates.ReadTrustBundleFile(cfg.CAFile)
		if e != nil {
			return nil, domain.Err(422, "invalid_service_trust")
		}
	}
	if len(ca) > 1024*1024 {
		return nil, domain.Err(422, "invalid_service_trust")
	}
	if len(ca) > 0 {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			return nil, domain.Err(422, "invalid_service_trust")
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	if (cfg.CertificateFile == "") != (cfg.KeyFile == "") {
		return nil, domain.Err(422, "invalid_client_certificate")
	}
	if cfg.CertificateFile != "" {
		cert, e := certificates.ReadPEMFile(cfg.CertificateFile, false)
		if e != nil {
			return nil, domain.Err(422, "invalid_client_certificate")
		}
		key, e := certificates.ReadPEMFile(cfg.KeyFile, true)
		if e != nil {
			return nil, domain.Err(422, "invalid_client_certificate")
		}
		pair, e := tls.X509KeyPair(cert, key)
		if e != nil {
			return nil, domain.Err(422, "invalid_client_certificate")
		}
		tlsConfig.Certificates = []tls.Certificate{pair}
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, DialContext: (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, MaxIdleConns: 32, MaxIdleConnsPerHost: 16, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: timeout}
	sleeper := cfg.Sleep
	if sleeper == nil {
		sleeper = func(ctx context.Context, d time.Duration) error {
			timer := time.NewTimer(d)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		}
	}
	return &Client{endpoint, provider, refreshable, retries, timeout, maximum, &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, sleeper}, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func safePath(path string) bool {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "?#\\\r\n\x00") {
		return false
	}
	decoded, e := url.PathUnescape(path)
	if e != nil || strings.ContainsAny(decoded, "?#\\\r\n\x00") {
		return false
	}
	for _, p := range strings.Split(decoded, "/") {
		if p == "." || p == ".." {
			return false
		}
	}
	return true
}
func safeErrorCode(code string) string {
	if code == "" || len(code) > 128 {
		return "request_failed"
	}
	for _, r := range code {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-') {
			return "request_failed"
		}
	}
	return code
}
func retryDelay(value string, attempt int) time.Duration {
	delay := time.Duration(1<<attempt) * time.Second
	if value != "" {
		if n, e := strconv.ParseFloat(value, 64); e == nil && n >= -86400 && n <= 86400 {
			if n < 0 {
				n = 0
			}
			if n > 60 {
				n = 60
			}
			delay = time.Duration(n * float64(time.Second))
		} else if at, e := http.ParseTime(value); e == nil {
			delay = time.Until(at)
		}
	}
	if delay < 0 {
		delay = 0
	}
	if delay > 60*time.Second {
		delay = 60 * time.Second
	}
	return delay
}
func requestFailure(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return domain.Err(408, "request_deadline_exceeded")
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return domain.Err(408, "request_cancelled")
	}
	return domain.Err(503, "connection_failed")
}

// Request retains the same encoded body and idempotency key across bounded retries.
// Callers must persist their operation key across process restarts.
func (c *Client) Request(ctx context.Context, method, path string, body any, headers map[string]string, query url.Values) (map[string]any, error) {
	method = strings.ToUpper(method)
	if !safePath(path) {
		return nil, domain.Err(422, "invalid_exchange_path")
	}
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE":
	default:
		return nil, domain.Err(422, "invalid_exchange_method")
	}
	var encoded []byte
	var e error
	if body != nil {
		encoded, e = domain.CanonicalJSON(body)
		if e != nil {
			return nil, domain.Err(422, "invalid_exchange_body")
		}
	}
	target := c.endpoint + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	fixedHeaders := http.Header{}
	for k, v := range headers {
		if strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "Proxy-Authorization") || strings.EqualFold(k, "Cookie") || strings.EqualFold(k, "Host") {
			return nil, domain.Err(422, "caller_credentials_forbidden")
		}
		if strings.ContainsAny(k+v, "\r\n\x00") {
			return nil, domain.Err(422, "invalid_exchange_headers")
		}
		fixedHeaders.Set(k, v)
	}
	retryable := method == "GET" || method == "HEAD" || method == "PUT" || method == "DELETE" || method == "PATCH" || fixedHeaders.Get("Idempotency-Key") != ""
	for attempt := 0; attempt < c.retries; attempt++ {
		if ctx.Err() != nil {
			return nil, requestFailure(ctx)
		}
		token, e := c.token(ctx)
		if e != nil {
			return nil, domain.Err(503, "credential_unavailable")
		}
		token, e = tokenValue(token)
		if e != nil {
			return nil, e
		}
		request, e := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(encoded))
		if e != nil {
			return nil, domain.Err(422, "invalid_exchange_request")
		}
		request.Header = fixedHeaders.Clone()
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Accept", "application/json")
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		response, e := c.http.Do(request)
		if e != nil {
			if retryable && attempt+1 < c.retries && ctx.Err() == nil {
				if e = c.sleep(ctx, retryDelay("", attempt)); e == nil {
					continue
				}
			}
			return nil, requestFailure(ctx)
		}
		raw, e := io.ReadAll(io.LimitReader(response.Body, c.maxResponse+1))
		response.Body.Close()
		if e != nil {
			return nil, requestFailure(ctx)
		}
		if int64(len(raw)) > c.maxResponse {
			return nil, domain.Err(502, "exchange_response_too_large")
		}
		if retryable && attempt+1 < c.retries && (response.StatusCode == 429 || response.StatusCode == 502 || response.StatusCode == 503 || response.StatusCode == 504) {
			if c.sleep(ctx, retryDelay(response.Header.Get("Retry-After"), attempt)) != nil {
				return nil, requestFailure(ctx)
			}
			continue
		}
		if response.StatusCode == 401 && c.refreshable && attempt+1 < c.retries {
			continue
		}
		if response.StatusCode == 204 {
			return map[string]any{}, nil
		}
		var result map[string]any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		parseErr := dec.Decode(&result)
		var trailing any
		if parseErr == nil && dec.Decode(&trailing) != io.EOF {
			parseErr = errors.New("trailing response content")
		}
		if response.StatusCode >= 300 {
			code := "request_failed"
			if parseErr == nil {
				errBody := result
				if v, ok := result["error"].(map[string]any); ok {
					errBody = v
				}
				if v, ok := errBody["code"].(string); ok {
					code = safeErrorCode(v)
				}
			}
			return nil, domain.Err(response.StatusCode, code)
		}
		if parseErr != nil || result == nil {
			return nil, domain.Err(502, "invalid_exchange_response")
		}
		return result, nil
	}
	return nil, domain.Err(503, "connection_failed")
}
func Path(space, suffix string) (string, error) {
	if checkedID(space) != nil {
		return "", domain.Err(422, "invalid_resource_identifier")
	}
	path := "/v2/spaces/" + space + suffix
	if !safePath(path) {
		return "", domain.Err(422, "invalid_exchange_path")
	}
	return path, nil
}
func PathFor(space, suffix string) string {
	p, e := Path(space, suffix)
	if e != nil {
		return ""
	}
	return p
}
func keyHeader(key string) map[string]string {
	if key == "" {
		key = domain.NewID()
	}
	return map[string]string{"Idempotency-Key": key}
}
func (c *Client) spaceRequest(ctx context.Context, method, space, suffix string, body any, headers map[string]string, query url.Values) (map[string]any, error) {
	p, e := Path(space, suffix)
	if e != nil {
		return nil, e
	}
	return c.Request(ctx, method, p, body, headers, query)
}
func (c *Client) CreateSpace(ctx context.Context, name, profile, key string, options map[string]any) (map[string]any, error) {
	if profile == "" {
		profile = "generic.v1"
	}
	body := map[string]any{}
	for k, v := range options {
		if k == "name" || k == "profile" {
			return nil, domain.Err(422, "invalid_space_options")
		}
		body[k] = v
	}
	body["name"] = name
	body["profile"] = profile
	return c.Request(ctx, "POST", "/v2/spaces", body, keyHeader(key), nil)
}
func (c *Client) GetSpace(ctx context.Context, space string) (map[string]any, error) {
	return c.spaceRequest(ctx, "GET", space, "", nil, nil, nil)
}
func (c *Client) UpdateSpaceLimits(ctx context.Context, space string, limits map[string]any) (map[string]any, error) {
	return c.spaceRequest(ctx, "PATCH", space, "", limits, nil, nil)
}
func (c *Client) ManageSpace(ctx context.Context, space, job, key string) (map[string]any, error) {
	return c.spaceRequest(ctx, "PUT", space, "/managed", map[string]any{"job_id": job}, keyHeader(key), nil)
}
func (c *Client) GetManagedSpace(ctx context.Context, space string) (map[string]any, error) {
	return c.spaceRequest(ctx, "GET", space, "/managed", nil, nil, nil)
}
func (c *Client) RetireManagedSpace(ctx context.Context, space, job, key string) (map[string]any, error) {
	return c.spaceRequest(ctx, "POST", space, "/managed/retire", map[string]any{"job_id": job}, keyHeader(key), nil)
}
func (c *Client) SetMember(ctx context.Context, space, principal string, roles []string, subject *string, bindings map[string]any) (map[string]any, error) {
	if checkedID(principal) != nil {
		return nil, domain.Err(422, "invalid_resource_identifier")
	}
	if bindings == nil {
		bindings = map[string]any{}
	}
	return c.spaceRequest(ctx, "PUT", space, "/members/"+principal, map[string]any{"roles": roles, "subject": subject, "bindings": bindings}, nil, nil)
}
func (c *Client) GetMembership(ctx context.Context, space string) (map[string]any, error) {
	return c.spaceRequest(ctx, "GET", space, "/membership", nil, nil, nil)
}
func (c *Client) Members(ctx context.Context, space string) (map[string]any, error) {
	return c.spaceRequest(ctx, "GET", space, "/members", nil, nil, nil)
}
func (c *Client) RegisterType(ctx context.Context, space, kind, key string, schema map[string]any, options map[string]any) (map[string]any, error) {
	if checkedID(kind) != nil {
		return nil, domain.Err(422, "invalid_resource_identifier")
	}
	body := map[string]any{"schema": schema}
	for k, v := range options {
		if k != "publish_roles" && k != "visibility" {
			return nil, domain.Err(422, "invalid_type_options")
		}
		body[k] = v
	}
	return c.spaceRequest(ctx, "POST", space, "/types/"+kind+"/revisions", body, keyHeader(key), nil)
}
func (c *Client) GetType(ctx context.Context, space, kind, revision string) (map[string]any, error) {
	if checkedID(kind) != nil || checkedID(revision) != nil {
		return nil, domain.Err(422, "invalid_resource_identifier")
	}
	return c.spaceRequest(ctx, "GET", space, "/types/"+kind+"/revisions/"+revision, nil, nil, nil)
}
func (c *Client) Types(ctx context.Context, space string) (map[string]any, error) {
	return c.spaceRequest(ctx, "GET", space, "/types", nil, nil, nil)
}
func (c *Client) SetPolicy(ctx context.Context, space, kind string, roles []string, visibility string) (map[string]any, error) {
	if checkedID(kind) != nil {
		return nil, domain.Err(422, "invalid_resource_identifier")
	}
	return c.spaceRequest(ctx, "PUT", space, "/policies/"+kind, map[string]any{"publish_roles": roles, "visibility": visibility}, nil, nil)
}
func (c *Client) CreateGrant(ctx context.Context, space, key string, body map[string]any) (map[string]any, error) {
	return c.spaceRequest(ctx, "POST", space, "/workload-grants", body, keyHeader(key), nil)
}
func (c *Client) GetGrant(ctx context.Context, space, grant string) (map[string]any, error) {
	if checkedID(grant) != nil {
		return nil, domain.Err(422, "invalid_resource_identifier")
	}
	return c.spaceRequest(ctx, "GET", space, "/workload-grants/"+grant, nil, nil, nil)
}
func (c *Client) GetWorkloadGrant(ctx context.Context, space, grant string) (map[string]any, error) {
	return c.GetGrant(ctx, space, grant)
}
func (c *Client) VerifyGrant(ctx context.Context, space string) (map[string]any, error) {
	return c.spaceRequest(ctx, "POST", space, "/workload-grants/verify", map[string]any{}, nil, nil)
}
func (c *Client) RevokeGrants(ctx context.Context, space, attempt, key string) (map[string]any, error) {
	return c.spaceRequest(ctx, "POST", space, "/workload-grants/revoke", map[string]any{"attempt_id": attempt}, keyHeader(key), nil)
}
func (c *Client) CreateRecord(ctx context.Context, space, key string, body map[string]any) (map[string]any, error) {
	return c.spaceRequest(ctx, "POST", space, "/records", body, keyHeader(key), nil)
}
func recordSuffix(record, tail string) (string, error) {
	if checkedID(record) != nil {
		return "", domain.Err(422, "invalid_resource_identifier")
	}
	return "/records/" + record + tail, nil
}
func (c *Client) GetRecord(ctx context.Context, space, record string) (map[string]any, error) {
	p, e := recordSuffix(record, "")
	if e != nil {
		return nil, e
	}
	return c.spaceRequest(ctx, "GET", space, p, nil, nil, nil)
}
func (c *Client) UpdateRecord(ctx context.Context, space, record string, metadata map[string]any, version int64) (map[string]any, error) {
	p, e := recordSuffix(record, "")
	if e != nil {
		return nil, e
	}
	return c.spaceRequest(ctx, "PATCH", space, p, map[string]any{"metadata": metadata}, map[string]string{"If-Match": "\"" + strconv.FormatInt(version, 10) + "\""}, nil)
}
func (c *Client) CancelRecord(ctx context.Context, space, record string) (map[string]any, error) {
	p, e := recordSuffix(record, "")
	if e != nil {
		return nil, e
	}
	return c.spaceRequest(ctx, "DELETE", space, p, nil, nil, nil)
}
func (c *Client) PurgeRecord(ctx context.Context, space, record string) (map[string]any, error) {
	p, e := recordSuffix(record, "/purge")
	if e != nil {
		return nil, e
	}
	return c.spaceRequest(ctx, "POST", space, p, nil, nil, nil)
}
func (c *Client) PublishRecord(ctx context.Context, space, record, key string) (map[string]any, error) {
	p, e := recordSuffix(record, "/publish")
	if e != nil {
		return nil, e
	}
	return c.spaceRequest(ctx, "POST", space, p, nil, keyHeader(key), nil)
}
func (c *Client) RecordsPage(ctx context.Context, space string, filters url.Values) (map[string]any, error) {
	return c.spaceRequest(ctx, "GET", space, "/records", nil, nil, filters)
}
func (c *Client) Events(ctx context.Context, space, cursor string, limit int) (map[string]any, error) {
	return c.spaceRequest(ctx, "GET", space, "/events", nil, nil, url.Values{"after": []string{cursor}, "limit": []string{strconv.Itoa(limit)}})
}
func (c *Client) GetReference(ctx context.Context, space, name string) (map[string]any, error) {
	if checkedID(name) != nil {
		return nil, domain.Err(422, "invalid_resource_identifier")
	}
	return c.spaceRequest(ctx, "GET", space, "/refs/"+name, nil, nil, nil)
}
func (c *Client) Resolve(ctx context.Context, space, name string) (map[string]any, error) {
	return c.GetReference(ctx, space, name)
}
func (c *Client) SetRef(ctx context.Context, space, name, record, key string, reference map[string]any) (map[string]any, error) {
	if checkedID(name) != nil || checkedID(record) != nil {
		return nil, domain.Err(422, "invalid_resource_identifier")
	}
	headers := keyHeader(key)
	if reference == nil {
		headers["If-None-Match"] = "*"
	} else {
		if reference["name"] != name {
			return nil, domain.Err(422, "reference_name_mismatch")
		}
		token, ok := reference["token"].(string)
		if !ok || token == "" || strings.ContainsAny(token, "\"\r\n") {
			return nil, domain.Err(422, "invalid_reference")
		}
		headers["If-Match"] = "\"" + token + "\""
	}
	return c.spaceRequest(ctx, "PUT", space, "/refs/"+name, map[string]any{"record_id": record}, headers, nil)
}
func (c *Client) Acquire(ctx context.Context, space, key string, body map[string]any) (map[string]any, error) {
	return c.spaceRequest(ctx, "POST", space, "/acquisitions", body, keyHeader(key), nil)
}
func (c *Client) GetAcquisition(ctx context.Context, space, id string) (map[string]any, error) {
	if checkedID(id) != nil {
		return nil, domain.Err(422, "invalid_resource_identifier")
	}
	return c.spaceRequest(ctx, "GET", space, "/acquisitions/"+id, nil, nil, nil)
}
func (c *Client) Renew(ctx context.Context, space, id string, fence int64) (map[string]any, error) {
	if checkedID(id) != nil {
		return nil, domain.Err(422, "invalid_resource_identifier")
	}
	return c.spaceRequest(ctx, "POST", space, "/acquisitions/"+id+"/renew", map[string]any{"fence": fence}, nil, nil)
}
func (c *Client) Abandon(ctx context.Context, space, id string, fence int64) (map[string]any, error) {
	if checkedID(id) != nil {
		return nil, domain.Err(422, "invalid_resource_identifier")
	}
	return c.spaceRequest(ctx, "POST", space, "/acquisitions/"+id+"/abandon", map[string]any{"fence": fence}, nil, nil)
}
func (c *Client) Complete(ctx context.Context, space, id, record, key string, fence int64) (map[string]any, error) {
	if checkedID(id) != nil || checkedID(record) != nil {
		return nil, domain.Err(422, "invalid_resource_identifier")
	}
	return c.spaceRequest(ctx, "POST", space, "/acquisitions/"+id+"/complete", map[string]any{"fence": fence, "result_record_id": record}, keyHeader(key), nil)
}
