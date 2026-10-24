package participants

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"golang.org/x/sys/unix"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
)

type ClientConfig struct {
	Endpoint, CAFile, CertificateFile, KeyFile string
	HTTP                                       *http.Client
}
type ManagerClient struct {
	Endpoint string
	HTTP     *http.Client
}

func NewManagerClient(cfg ClientConfig) (*ManagerClient, error) {
	u, e := url.Parse(cfg.Endpoint)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(cfg.Endpoint, "\r\n\x00") {
		return nil, domain.Err(422, "invalid_manager_endpoint")
	}
	client := cfg.HTTP
	if client == nil {
		config := &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.CAFile != "" {
			b, e := readClientFile(cfg.CAFile, false)
			if e != nil {
				return nil, e
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(b) {
				return nil, domain.Err(422, "invalid_manager_tls")
			}
			config.RootCAs = roots
		}
		if cfg.CertificateFile == "" || cfg.KeyFile == "" {
			return nil, domain.Err(422, "participant_certificate_required")
		}
		cert, e := readClientFile(cfg.CertificateFile, false)
		if e != nil {
			return nil, e
		}
		key, e := readClientFile(cfg.KeyFile, true)
		if e != nil {
			return nil, e
		}
		pair, e := tls.X509KeyPair(cert, key)
		if e != nil {
			return nil, domain.Err(422, "invalid_manager_tls")
		}
		config.Certificates = []tls.Certificate{pair}
		client = &http.Client{Transport: &http.Transport{TLSClientConfig: config, Proxy: nil, DisableCompression: true, MaxIdleConns: 8, IdleConnTimeout: 30 * time.Second}, Timeout: 60 * time.Second}
	} else {
		copy := *client
		client = &copy
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &ManagerClient{Endpoint: strings.TrimSuffix(cfg.Endpoint, "/"), HTTP: client}, nil
}
func readClientFile(path string, private bool) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, domain.Err(422, "invalid_manager_tls")
	}
	parent, e := cleanupOpenAbsolute(filepath.Dir(path))
	if e != nil {
		return nil, domain.Err(422, "invalid_manager_tls")
	}
	defer unix.Close(parent)
	fd, e := unix.Openat(parent, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, domain.Err(422, "invalid_manager_tls")
	}
	f := os.NewFile(uintptr(fd), "participant-tls")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0022 != 0 || st.Size < 0 || st.Size > 65536 || (private && (st.Mode&0077 != 0 || st.Uid != uint32(os.Geteuid()))) {
		return nil, domain.Err(422, "invalid_manager_tls")
	}
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(b) > 65536 || int64(len(b)) != st.Size {
		return nil, domain.Err(422, "invalid_manager_tls")
	}
	return b, nil
}
func (c *ManagerClient) Close() {
	if c != nil && c.HTTP != nil {
		c.HTTP.CloseIdleConnections()
	}
}
func participantPath(id executor.ExecutionIdentity, operation string) (string, error) {
	if e := id.Validate(); e != nil {
		return "", e
	}
	methodOp := operation
	fixed := map[string]bool{"plan": true, "control": true, "purge-plan": true, "assignment": true, "certificate": true, "credentials": true, "heartbeat": true, "stopped": true, "logs": true, "purged": true}
	if !fixed[operation] {
		if strings.HasPrefix(operation, "source/") {
			methodOp = strings.TrimPrefix(operation, "source/")
		} else if strings.HasPrefix(operation, "build-products/") {
			methodOp = strings.TrimPrefix(operation, "build-products/")
		} else {
			return "", domain.Err(422, "invalid_participant_operation")
		}
		if !safeRelative(methodOp) {
			return "", domain.Err(422, "invalid_participant_operation")
		}
	}
	parts := strings.Split(operation, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return "/internal/jobs/v1/participants/" + url.PathEscape(id.JobID) + "/" + url.PathEscape(id.AttemptID) + "/" + url.PathEscape(id.ComponentID) + "/" + strconv.FormatInt(id.Epoch, 10) + "/" + strings.Join(parts, "/"), nil
}
func safeRelative(path string) bool {
	if path == "" || len(path) > 1024 || strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\\\x00\r\n") {
		return false
	}
	parts := strings.Split(path, "/")
	if len(parts) > 64 {
		return false
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	return true
}
func (c *ManagerClient) request(ctx context.Context, id executor.ExecutionIdentity, token, operation string, body any, raw bool) ([]byte, error) {
	if c == nil || c.HTTP == nil {
		return nil, domain.Err(503, "external_manager_unavailable")
	}
	if token == "" || len(token) > 16384 || strings.ContainsAny(token, "\r\n") {
		return nil, domain.Err(401, "invalid_node_grant")
	}
	path, e := participantPath(id, operation)
	if e != nil {
		return nil, e
	}
	method := "POST"
	if operation == "plan" || operation == "control" || operation == "purge-plan" || strings.HasPrefix(operation, "source/") || strings.HasPrefix(operation, "build-products/") {
		method = "GET"
	}
	var data []byte
	if body != nil {
		data, e = domain.CanonicalJSON(body)
		if e != nil {
			return nil, domain.Err(422, "invalid_participant_request")
		}
	}
	timeout := 60 * time.Second
	if operation == "logs" {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, method, c.Endpoint+path, bytes.NewReader(data))
	if e != nil {
		return nil, domain.Err(503, "external_manager_unavailable")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept-Encoding", "identity")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, e := c.HTTP.Do(req)
	if e != nil {
		return nil, domain.Err(503, "external_manager_unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return nil, domain.Err(503, "external_manager_redirect_forbidden")
	}
	encoding := response.Header.Get("Content-Encoding")
	if encoding != "" && encoding != "identity" {
		return nil, domain.Err(502, "invalid_external_manager_reply")
	}
	bound := int64(16 << 20)
	if raw {
		bound = 64 << 20
	}
	content, e := io.ReadAll(io.LimitReader(response.Body, bound+1))
	if e != nil {
		return nil, domain.Err(503, "external_manager_unavailable")
	}
	if int64(len(content)) > bound {
		return nil, domain.Err(502, "external_manager_reply_too_large")
	}
	if response.StatusCode >= 400 {
		code := "external_manager_unavailable"
		if v, e := domain.DecodeJSON(content); e == nil {
			if c := str(mapv(mapv(v)["error"])["code"]); c != "" {
				code = c
			}
		}
		return nil, domain.Err(response.StatusCode, code)
	}
	if response.StatusCode < 200 {
		return nil, domain.Err(502, "invalid_external_manager_reply")
	}
	return content, nil
}
func (c *ManagerClient) Request(ctx context.Context, id executor.ExecutionIdentity, token, operation string, body any) (map[string]any, error) {
	b, e := c.request(ctx, id, token, operation, body, false)
	if e != nil {
		return nil, e
	}
	v, e := domain.DecodeJSON(b)
	if e != nil {
		return nil, domain.Err(502, "invalid_external_manager_reply")
	}
	out, ok := v.(map[string]any)
	if !ok {
		return nil, domain.Err(502, "invalid_external_manager_reply")
	}
	return out, nil
}
func (c *ManagerClient) Raw(ctx context.Context, id executor.ExecutionIdentity, token, operation string) ([]byte, error) {
	return c.request(ctx, id, token, operation, nil, true)
}

// DispatchClient invokes only operator-approved HTTPS participant origins.
type DispatchClient struct {
	Nodes   map[string]string
	Clients map[string]*http.Client
}

func NewDispatchClient(nodes map[string]ClientConfig) (*DispatchClient, error) {
	d := &DispatchClient{Nodes: map[string]string{}, Clients: map[string]*http.Client{}}
	for id, cfg := range nodes {
		if domain.ValidateIdentifier(id) != nil {
			return nil, domain.Err(422, "invalid_external_node")
		}
		client, e := NewManagerClient(cfg)
		if e != nil {
			return nil, e
		}
		d.Nodes[id] = client.Endpoint
		d.Clients[id] = client.HTTP
	}
	return d, nil
}
func (d *DispatchClient) Dispatch(ctx context.Context, nodeID string, document map[string]any) (map[string]any, error) {
	origin, ok := d.Nodes[nodeID]
	if !ok {
		return nil, domain.Err(503, "external_node_dispatch_unavailable")
	}
	b, e := domain.CanonicalJSON(document)
	if e != nil {
		return nil, domain.Err(422, "invalid_participant_dispatch")
	}
	duration := 90 * time.Second
	if str(document["operation"]) == "publication-state" {
		duration = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, "POST", origin+"/internal/nodes/v1/participants", bytes.NewReader(b))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	response, e := d.Clients[nodeID].Do(req)
	if e != nil {
		return nil, domain.Err(503, "external_node_dispatch_unavailable")
	}
	defer response.Body.Close()
	limit := int64(16 << 20)
	content, e := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if e != nil || int64(len(content)) > limit {
		return nil, domain.Err(502, "invalid_external_node_reply")
	}
	if response.StatusCode >= 300 {
		return nil, domain.Err(503, "external_node_dispatch_unavailable")
	}
	v, e := domain.DecodeJSON(content)
	if e != nil {
		return nil, domain.Err(502, "invalid_external_node_reply")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, domain.Err(502, "invalid_external_node_reply")
	}
	return m, nil
}
func (d *DispatchClient) Close() {
	for _, c := range d.Clients {
		c.CloseIdleConnections()
	}
}
func sameMap(a, b any) bool {
	aa, e := domain.CanonicalJSON(a)
	if e != nil {
		return false
	}
	bb, e := domain.CanonicalJSON(b)
	return e == nil && bytes.Equal(aa, bb)
}
func (c *ManagerClient) Stream(ctx context.Context, id executor.ExecutionIdentity, token, operation string, expectedSize int64, consume func(int64, []byte) error) error {
	if c == nil || c.HTTP == nil || consume == nil || expectedSize < 1 || expectedSize > 1<<40 || !strings.HasPrefix(operation, "build-products/") {
		return domain.Err(422, "invalid_external_build_request")
	}
	path, e := participantPath(id, operation)
	if e != nil {
		return e
	}
	if token == "" || len(token) > 16384 || strings.ContainsAny(token, "\r\n") {
		return domain.Err(401, "node_grant_required")
	}
	request, e := http.NewRequestWithContext(ctx, "GET", c.Endpoint+path, nil)
	if e != nil {
		return domain.Err(503, "external_build_unavailable")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept-Encoding", "identity")
	response, e := c.HTTP.Do(request)
	if e != nil {
		return domain.Err(503, "external_build_unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return domain.Err(503, "external_manager_redirect_forbidden")
	}
	if response.StatusCode >= 400 {
		return domain.Err(response.StatusCode, "external_build_unavailable")
	}
	if response.StatusCode != 200 {
		return domain.Err(502, "external_build_invalid_reply")
	}
	encoding := response.Header.Get("Content-Encoding")
	if encoding != "" && encoding != "identity" {
		return domain.Err(502, "external_build_invalid_reply")
	}
	if response.ContentLength >= 0 && response.ContentLength != expectedSize {
		return domain.Err(502, "external_build_size_mismatch")
	}
	offset := int64(0)
	buffer := make([]byte, 65536)
	for {
		count, readErr := response.Body.Read(buffer)
		if count > 0 {
			if int64(count) > expectedSize-offset {
				return domain.Err(502, "external_build_size_mismatch")
			}
			if e = consume(offset, buffer[:count]); e != nil {
				return e
			}
			offset += int64(count)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return domain.Err(503, "external_build_unavailable")
		}
		if count == 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
		}
	}
	if offset != expectedSize {
		return domain.Err(502, "external_build_size_mismatch")
	}
	return nil
}
