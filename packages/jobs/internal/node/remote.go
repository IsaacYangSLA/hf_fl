package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/certificates"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
)

func readTLSFile(path string, private bool) ([]byte, error) {
	data, e := certificates.ReadPEMFile(path, private)
	if e != nil {
		return nil, domain.Err(409, "unsafe_node_credentials")
	}
	return data, nil
}

func (e NodeEndpoint) Client() (*http.Client, error) {
	e = e.Defaults()
	if err := e.Validate(); err != nil {
		return nil, err
	}
	ca, err := readTLSFile(e.CAFile, false)
	if err != nil {
		return nil, err
	}
	certPEM, err := readTLSFile(e.ClientCertificate, false)
	if err != nil {
		return nil, err
	}
	keyPEM, err := readTLSFile(e.ClientKey, true)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, domain.Err(409, "unsafe_node_credentials")
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, domain.Err(409, "unsafe_node_credentials")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{cert}}, DisableCompression: true}
	return &http.Client{Transport: transport, Timeout: time.Duration(e.TimeoutSeconds * float64(time.Second)), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

type PreparedExecution struct {
	RuntimeConfig    map[string]any
	ExecutionBinding map[string]any
	BuildProducts    map[string][]byte
}
type RemoteConfig struct {
	Endpoints          map[string]NodeEndpoint
	Route              func(context.Context, executor.ExecutionIdentity, string) (NodeRoute, error)
	AssignmentProvider func(context.Context, executor.ExecutionSpec, NodeRoute) (RemoteAssignment, error)
	TokenProvider      func(context.Context, NodeRoute, executor.ExecutionIdentity, string) (string, error)
	PreparedProvider   func(context.Context, executor.ExecutionIdentity) (PreparedExecution, error)
	ClientFactory      func(NodeEndpoint) (*http.Client, error)
}
type RemoteExecutor struct {
	config  RemoteConfig
	clients map[string]*http.Client
}

func NewRemoteExecutor(config RemoteConfig) (*RemoteExecutor, error) {
	if config.Route == nil || config.AssignmentProvider == nil || config.TokenProvider == nil || len(config.Endpoints) == 0 {
		return nil, domain.Err(409, "invalid_node_endpoint")
	}
	original := config.Endpoints
	config.Endpoints = make(map[string]NodeEndpoint, len(original))
	out := &RemoteExecutor{config: config, clients: map[string]*http.Client{}}
	for key, e := range original {
		e = e.Defaults()
		if key != e.NodeID {
			return nil, domain.Err(409, "invalid_node_endpoint")
		}
		if err := e.Validate(); err != nil {
			return nil, err
		}
		config.Endpoints[key] = e
		factory := config.ClientFactory
		if factory == nil {
			factory = func(e NodeEndpoint) (*http.Client, error) { return e.Client() }
		}
		c, err := factory(e)
		if err != nil {
			return nil, err
		}
		out.clients[key] = c
	}
	return out, nil
}
func (r *RemoteExecutor) Close() {
	for _, c := range r.clients {
		c.CloseIdleConnections()
	}
}
func (r *RemoteExecutor) route(ctx context.Context, id executor.ExecutionIdentity, pool string) (NodeRoute, error) {
	if err := id.Validate(); err != nil {
		return NodeRoute{}, err
	}
	route, err := r.config.Route(ctx, id, pool)
	if err != nil {
		return route, err
	}
	route.Resources = route.Resources.Defaults()
	if err = route.Validate(); err != nil {
		return route, err
	}
	if _, ok := r.clients[route.NodeID]; !ok {
		return route, domain.Err(409, "node_not_approved")
	}
	if pool != "" && route.PoolID != pool {
		return route, domain.Err(409, "pool_mismatch")
	}
	return route, nil
}
func uncertain(err error) error { return &executor.UncertainError{Cause: err} }
func boundedReply(ctx context.Context, client *http.Client, endpoint NodeEndpoint, method, path, token string, body any, limit int64, raw bool) ([]byte, error) {
	if limit < 0 || limit > 1<<30 {
		return nil, domain.Err(409, "invalid_assignment")
	}
	content, e := json.Marshal(body)
	if e != nil {
		return nil, domain.Err(409, "invalid_assignment")
	}
	req, e := http.NewRequestWithContext(ctx, method, endpoint.Origin+path, bytes.NewReader(content))
	if e != nil {
		return nil, domain.Err(409, "invalid_node_endpoint")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, e := client.Do(req)
	if e != nil {
		return nil, uncertain(e)
	}
	defer response.Body.Close()
	data, e := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if e != nil || int64(len(data)) > limit {
		return nil, uncertain(errors.New("bounded node reply unavailable"))
	}
	if response.StatusCode >= 500 || response.StatusCode >= 300 && response.StatusCode < 400 {
		return nil, uncertain(errors.New("node outcome unknown"))
	}
	if response.StatusCode >= 400 {
		code := "node_operation_refused"
		var b struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if json.Unmarshal(data, &b) == nil && len(b.Error.Code) > 0 && len(b.Error.Code) <= 128 {
			code = b.Error.Code
		}
		return nil, domain.Err(409, code)
	}
	if !raw && !json.Valid(data) {
		return nil, uncertain(errors.New("invalid node receipt"))
	}
	return data, nil
}
func (r *RemoteExecutor) post(ctx context.Context, route NodeRoute, id executor.ExecutionIdentity, op string, body any, rawLimit *int64) ([]byte, error) {
	scope := map[string]string{"prepare": "assignment", "binding": "assignment", "stage-build": "assignment", "proxy-alive": "inspect", "health": "heartbeat", "read-artifact": "collect", "read-state": "collect", "read-logs": "logs"}[op]
	if scope == "" {
		scope = op
	}
	token, e := r.config.TokenProvider(ctx, route, id, scope)
	if e != nil {
		return nil, e
	}
	if token == "" || len(token) > 16384 {
		return nil, domain.Err(409, "node_grant_unavailable")
	}
	endpoint := r.config.Endpoints[route.NodeID]
	limit := endpoint.MaxReplyBytes
	if rawLimit != nil {
		limit = *rawLimit
	}
	return boundedReply(ctx, r.clients[route.NodeID], endpoint, "POST", "/internal/nodes/v1/"+op, token, body, limit, rawLimit != nil)
}
func (r *RemoteExecutor) Reserve(ctx context.Context, spec executor.ExecutionSpec) (executor.Reservation, error) {
	spec = spec.Defaults()
	route, e := r.route(ctx, spec.Identity, spec.PoolID)
	if e != nil {
		return executor.Reservation{}, e
	}
	if route.Resources != spec.Resources {
		return executor.Reservation{}, domain.Err(409, "invalid_resources")
	}
	a, e := r.config.AssignmentProvider(ctx, spec, route)
	if e != nil {
		return executor.Reservation{}, e
	}
	a = a.Defaults()
	if a.Validate() != nil || a.Identity != spec.Identity || a.NodeID != route.NodeID || a.PoolID != route.PoolID || a.Resources != route.Resources {
		return executor.Reservation{}, domain.Err(409, "assignment_conflict")
	}
	b, e := r.post(ctx, route, spec.Identity, "reserve", map[string]any{"assignment": a}, nil)
	if e != nil {
		return executor.Reservation{}, e
	}
	var receipt executor.Reservation
	if strictDecode(b, &receipt) != nil || receipt.Identity != spec.Identity || receipt.NodeID != route.NodeID || !receipt.Acknowledged {
		return receipt, uncertain(errors.New("foreign reservation receipt"))
	}
	return receipt, nil
}
func (r *RemoteExecutor) observe(ctx context.Context, id executor.ExecutionIdentity, op string, values map[string]any) (executor.RuntimeObservation, error) {
	route, e := r.route(ctx, id, "")
	if e != nil {
		return executor.RuntimeObservation{}, e
	}
	body := map[string]any{"identity": id}
	for k, v := range values {
		body[k] = v
	}
	b, e := r.post(ctx, route, id, op, body, nil)
	if e != nil {
		return executor.RuntimeObservation{}, e
	}
	var out executor.RuntimeObservation
	if strictDecode(b, &out) != nil || out.Identity != id {
		return out, uncertain(errors.New("foreign observation receipt"))
	}
	valid := map[string]bool{"RESERVING": true, "RESERVED": true, "STARTING": true, "RUNNING": true, "STOPPING": true, "STOPPED": true, "EXITED": true, "RELEASED": true, "QUARANTINED": true, "UNKNOWN": true}
	if !valid[out.State] || out.Metrics == nil {
		return out, uncertain(errors.New("invalid observation state"))
	}
	for _, v := range out.Metrics {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return out, uncertain(errors.New("invalid observation metrics"))
		}
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(b, &fields)
	if v, ok := fields["termination_confirmed"]; !ok || (string(v) != "true" && string(v) != "false") {
		return out, uncertain(errors.New("unconfirmed observation"))
	}
	return out, nil
}
func (r *RemoteExecutor) Start(ctx context.Context, id executor.ExecutionIdentity) (executor.RuntimeObservation, error) {
	if r.config.PreparedProvider != nil {
		v, e := r.config.PreparedProvider(ctx, id)
		if e != nil {
			return executor.RuntimeObservation{}, e
		}
		if _, e = r.Prepare(ctx, id, v.RuntimeConfig, v.ExecutionBinding, v.BuildProducts); e != nil {
			return executor.RuntimeObservation{}, e
		}
	}
	return r.observe(ctx, id, "start", nil)
}
func (r *RemoteExecutor) Inspect(ctx context.Context, id executor.ExecutionIdentity) (executor.RuntimeObservation, error) {
	return r.observe(ctx, id, "inspect", nil)
}
func (r *RemoteExecutor) Stop(ctx context.Context, id executor.ExecutionIdentity, grace int) (executor.RuntimeObservation, error) {
	if grace < 0 || grace > 60 {
		return executor.RuntimeObservation{}, domain.Err(409, "invalid_assignment")
	}
	return r.observe(ctx, id, "stop", map[string]any{"grace_seconds": grace})
}
func (r *RemoteExecutor) confirmed(ctx context.Context, id executor.ExecutionIdentity, op string, values map[string]any) (bool, error) {
	route, e := r.route(ctx, id, "")
	if e != nil {
		return false, e
	}
	body := map[string]any{"identity": id}
	for k, v := range values {
		body[k] = v
	}
	b, e := r.post(ctx, route, id, op, body, nil)
	if e != nil {
		return false, e
	}
	var out struct {
		Confirmed bool `json:"confirmed"`
	}
	if strictDecode(b, &out) != nil || !out.Confirmed {
		return false, uncertain(errors.New("node completion unconfirmed"))
	}
	return true, nil
}
func (r *RemoteExecutor) Renew(ctx context.Context, id executor.ExecutionIdentity) error {
	return r.RenewLease(ctx, id, 120)
}
func (r *RemoteExecutor) RenewLease(ctx context.Context, id executor.ExecutionIdentity, seconds float64) error {
	if seconds <= 0 || seconds > 300 || math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		return domain.Err(409, "invalid_lease")
	}
	_, e := r.confirmed(ctx, id, "renew", map[string]any{"lease_seconds": seconds})
	return e
}

func (r *RemoteExecutor) Release(ctx context.Context, id executor.ExecutionIdentity) (bool, error) {
	return r.confirmed(ctx, id, "release", nil)
}
func (r *RemoteExecutor) Prepare(ctx context.Context, id executor.ExecutionIdentity, config, binding map[string]any, products map[string][]byte) (bool, error) {
	declared, ok := config["built_artifacts"].(map[string]any)
	if !ok && config["built_artifacts"] != nil {
		return false, domain.Err(409, "invalid_assignment")
	}
	if len(declared) != len(products) {
		return false, domain.Err(409, "build_inputs_missing")
	}
	route, e := r.route(ctx, id, "")
	if e != nil {
		return false, e
	}
	limit := int64(256 << 20)
	if route.Resources.DiskBytes < limit {
		limit = route.Resources.DiskBytes
	}
	var total int64
	names := make([]string, 0, len(products))
	for name := range products {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data := products[name]
		total += int64(len(data))
		if total > limit {
			return false, domain.Err(409, "invalid_assignment")
		}
		d, ok := declared[name].(map[string]any)
		if !ok {
			return false, domain.Err(409, "unsafe_output")
		}
		h := sha256.Sum256(data)
		if number(d["size_bytes"]) != int64(len(data)) || d["sha256"] != hex.EncodeToString(h[:]) {
			return false, domain.Err(409, "unsafe_output")
		}
		for offset := 0; offset < len(data); offset += 1 << 20 {
			end := offset + (1 << 20)
			if end > len(data) {
				end = len(data)
			}
			if _, e = r.confirmed(ctx, id, "stage-build", map[string]any{"artifacts": declared, "filename": name, "offset": offset, "data_base64": base64.StdEncoding.EncodeToString(data[offset:end])}); e != nil {
				return false, e
			}
		}
	}
	return r.confirmed(ctx, id, "prepare", map[string]any{"runtime_config": config, "execution_binding": binding})
}
func (r *RemoteExecutor) Binding(ctx context.Context, id executor.ExecutionIdentity, space, principal string) (map[string]any, error) {
	route, e := r.route(ctx, id, "")
	if e != nil {
		return nil, e
	}
	b, e := r.post(ctx, route, id, "binding", map[string]any{"identity": id, "space_id": space, "principal_id": principal}, nil)
	if e != nil {
		return nil, e
	}
	var out map[string]any
	if strictDecode(b, &out) != nil {
		return nil, uncertain(errors.New("invalid binding receipt"))
	}
	return out, nil
}
func (r *RemoteExecutor) PurgeReceipt(ctx context.Context, id executor.ExecutionIdentity, specDigest string) (NodePurgeReceipt, error) {
	route, e := r.route(ctx, id, "")
	if e != nil {
		return NodePurgeReceipt{}, e
	}
	body := map[string]any{"identity": id}
	if specDigest != "" {
		body["spec_digest"] = specDigest
	}
	b, e := r.post(ctx, route, id, "purge", body, nil)
	if e != nil {
		return NodePurgeReceipt{}, e
	}
	var out NodePurgeReceipt
	if strictDecode(b, &out) != nil || out.Validate() != nil || out.Identity() != id || out.NodeID != route.NodeID || out.PoolID != route.PoolID || specDigest != "" && out.SpecDigest != specDigest {
		return out, uncertain(errors.New("invalid owned purge receipt"))
	}
	return out, nil
}
func (r *RemoteExecutor) Purge(ctx context.Context, id executor.ExecutionIdentity) (bool, error) {
	v, e := r.PurgeReceipt(ctx, id, "")
	return v.Confirmed, e
}
func safeRelative(path string) bool {
	if path == "" || strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\\\x00\r\n") {
		return false
	}
	for _, p := range strings.Split(path, "/") {
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	return len(path) <= 4096
}
func (r *RemoteExecutor) Collect(ctx context.Context, id executor.ExecutionIdentity) ([]executor.CollectedArtifact, error) {
	route, e := r.route(ctx, id, "")
	if e != nil {
		return nil, e
	}
	b, e := r.post(ctx, route, id, "collect", map[string]any{"identity": id}, nil)
	if e != nil {
		return nil, e
	}
	var out []executor.CollectedArtifact
	if strictDecode(b, &out) != nil || len(out) > 1000 {
		return nil, uncertain(errors.New("invalid artifact inventory"))
	}
	for i := range out {
		a := &out[i]
		if !safeRelative(a.Path) || a.SizeBytes < 0 || !digestPattern.MatchString(a.SHA256) || a.Locator != "" {
			return nil, uncertain(errors.New("invalid artifact receipt"))
		}
		parts := strings.Split(a.Path, "/")
		for j, p := range parts {
			parts[j] = url.PathEscape(p)
		}
		a.Locator = "hf2l-node://" + route.NodeID + "/" + id.Key() + "/" + strings.Join(parts, "/")
	}
	return out, nil
}
func (r *RemoteExecutor) readBytes(ctx context.Context, id executor.ExecutionIdentity, path string, max int64, op string) ([]byte, error) {
	if max < 0 || max > 1<<30 || !safeRelative(path) {
		return nil, domain.Err(409, "invalid_assignment")
	}
	route, e := r.route(ctx, id, "")
	if e != nil {
		return nil, e
	}
	if route.Resources.DiskBytes < max {
		max = route.Resources.DiskBytes
	}
	return r.post(ctx, route, id, op, map[string]any{"identity": id, "path": path, "max_bytes": max}, &max)
}
func (r *RemoteExecutor) ReadArtifact(ctx context.Context, id executor.ExecutionIdentity, path string, max int64) ([]byte, error) {
	return r.readBytes(ctx, id, path, max, "read-artifact")
}
func (r *RemoteExecutor) ReadState(ctx context.Context, id executor.ExecutionIdentity, path string, max int64) ([]byte, error) {
	v, e := r.readBytes(ctx, id, path, max, "read-state")
	var d *domain.Error
	if errors.As(e, &d) && d.Code == "state_file_missing" {
		return nil, nil
	}
	return v, e
}
func (r *RemoteExecutor) ReadLogs(ctx context.Context, id executor.ExecutionIdentity, offset, max int64) (map[string]any, error) {
	if offset < 0 || max < 4 || max > 65536 {
		return nil, domain.Err(409, "invalid_assignment")
	}
	route, e := r.route(ctx, id, "")
	if e != nil {
		return nil, e
	}
	b, e := r.post(ctx, route, id, "read-logs", map[string]any{"identity": id, "offset": offset, "max_bytes": max}, nil)
	if e != nil {
		return nil, e
	}
	var v map[string]any
	if strictDecode(b, &v) != nil || len(v) != 7 {
		return nil, uncertain(errors.New("invalid log receipt"))
	}
	expected, _ := domain.CanonicalJSON(id)
	got, _ := domain.CanonicalJSON(v["identity"])
	text, ok := v["content"].(string)
	next := number(v["next_offset"])
	if !ok || string(got) != string(expected) || v["source_id"] != id.Key() || number(v["offset"]) != offset || next < offset || next > 1<<20 || int64(len(text)) > max || next-offset != int64(len(text)) {
		return nil, uncertain(errors.New("invalid log receipt"))
	}
	if _, ok = v["complete"].(bool); !ok {
		return nil, uncertain(errors.New("invalid log receipt"))
	}
	if _, ok = v["truncated"].(bool); !ok {
		return nil, uncertain(errors.New("invalid log receipt"))
	}
	return v, nil
}
func (r *RemoteExecutor) ProxyAlive(ctx context.Context, id executor.ExecutionIdentity) (bool, error) {
	route, e := r.route(ctx, id, "")
	if e != nil {
		return false, e
	}
	b, e := r.post(ctx, route, id, "proxy-alive", map[string]any{"identity": id}, nil)
	if e != nil {
		return false, e
	}
	var v struct {
		Identity executor.ExecutionIdentity `json:"identity"`
		Alive    *bool                      `json:"alive"`
	}
	if strictDecode(b, &v) != nil || v.Identity != id || v.Alive == nil {
		return false, uncertain(errors.New("invalid liveness receipt"))
	}
	return *v.Alive, nil
}
func (r *RemoteExecutor) Health(ctx context.Context, id executor.ExecutionIdentity) (map[string]any, error) {
	route, e := r.route(ctx, id, "")
	if e != nil {
		return nil, e
	}
	b, e := r.post(ctx, route, id, "health", map[string]any{"identity": id, "resources": route.Resources}, nil)
	if e != nil {
		return nil, e
	}
	var v map[string]any
	if strictDecode(b, &v) != nil || v["node_id"] != route.NodeID || v["pool_id"] != route.PoolID || v["healthy"] != true {
		return nil, domain.Err(409, "runtime_unhealthy")
	}
	return v, nil
}
func number(v any) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	case json.Number:
		i, e := n.Int64()
		if e == nil {
			return i
		}
	case float64:
		if !math.IsNaN(n) && !math.IsInf(n, 0) && n == math.Trunc(n) && n >= math.MinInt64 && n < math.MaxInt64 {
			return int64(n)
		}
	}
	return math.MinInt64
}
func numericEqual(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if number(v) == math.MinInt64 || number(v) != number(b[k]) {
			return false
		}
	}
	return true
}
func mapsEqual(a, b any) bool {
	aa, e := domain.CanonicalJSON(a)
	if e != nil {
		return false
	}
	bb, e := domain.CanonicalJSON(b)
	return e == nil && bytes.Equal(aa, bb)
}
func assignmentPath(prefix string, id executor.ExecutionIdentity, op string) string {
	return "/internal/jobs/v1/" + prefix + "/" + id.JobID + "/" + id.AttemptID + "/" + id.ComponentID + "/" + strconv.FormatInt(id.Epoch, 10) + "/" + op
}

type CredentialClient struct {
	Endpoint      NodeEndpoint
	RoutePrefix   string
	HTTP          *http.Client
	TokenProvider func(context.Context, executor.ExecutionIdentity, string) (string, error)
}

func NewCredentialClient(endpoint NodeEndpoint, prefix string) (*CredentialClient, error) {
	endpoint = endpoint.Defaults()
	if prefix != "nodes" && prefix != "participants" {
		return nil, domain.Err(409, "invalid_node_endpoint")
	}
	c, e := endpoint.Client()
	if e != nil {
		return nil, e
	}
	return &CredentialClient{Endpoint: endpoint, RoutePrefix: prefix, HTTP: c}, nil
}
func (c *CredentialClient) Close() { c.HTTP.CloseIdleConnections() }
func (c *CredentialClient) Request(ctx context.Context, id executor.ExecutionIdentity, op, method string, body any) (map[string]any, error) {
	if e := id.Validate(); e != nil {
		return nil, e
	}
	if method == "" {
		method = "POST"
	}
	if !map[string]bool{"bootstrap": true, "plan": true, "certificate": true, "credentials": true, "validate": true, "ack": true, "heartbeat": true, "progress": true, "logs": true, "stopped": true}[op] {
		return nil, domain.Err(409, "invalid_assignment")
	}
	token := ""
	var e error
	if op != "bootstrap" {
		if c.TokenProvider != nil {
			token, e = c.TokenProvider(ctx, id, op)
		} else {
			var v map[string]any
			v, e = c.Request(ctx, id, "bootstrap", "POST", map[string]any{})
			if e == nil {
				token, _ = v["token"].(string)
			}
		}
		if e != nil {
			return nil, e
		}
		if token == "" || len(token) > 16384 {
			return nil, domain.Err(409, "node_grant_unavailable")
		}
	}
	b, e := boundedReply(ctx, c.HTTP, c.Endpoint, method, assignmentPath(c.RoutePrefix, id, op), token, body, c.Endpoint.MaxReplyBytes, false)
	if e != nil {
		var de *domain.Error
		if errors.As(e, &de) {
			return nil, domain.Err(409, "node_assignment_refused")
		}
		return nil, e
	}
	var out map[string]any
	if strictDecode(b, &out) != nil || out == nil {
		return nil, uncertain(errors.New("invalid central node receipt"))
	}
	return out, nil
}
func (c *CredentialClient) Assignment(ctx context.Context, id executor.ExecutionIdentity) (map[string]any, error) {
	return c.Request(ctx, id, "plan", "GET", nil)
}
func (c *CredentialClient) Certificate(ctx context.Context, id executor.ExecutionIdentity, csr, space, principal string) (map[string]any, error) {
	if len(csr) < 1 || len(csr) > 16384 {
		return nil, domain.Err(409, "invalid_assignment")
	}
	return c.Request(ctx, id, "certificate", "POST", map[string]any{"csr_pem": csr, "space_id": space, "principal_id": principal})
}
func (c *CredentialClient) Credentials(ctx context.Context, id executor.ExecutionIdentity, thumb, audience string) (string, error) {
	if audience != "exchange" && audience != "gateway" {
		return "", domain.Err(409, "invalid_assignment")
	}
	body := map[string]any{}
	if c.RoutePrefix == "nodes" {
		body = map[string]any{"certificate_thumbprint": thumb, "audience": audience}
	}
	v, e := c.Request(ctx, id, "credentials", "POST", body)
	if e != nil {
		return "", e
	}
	field := "token"
	if c.RoutePrefix == "participants" {
		field = audience + "_token"
	}
	token, _ := v[field].(string)
	if token == "" || len(token) > 16384 {
		return "", uncertain(errors.New("invalid workload credential receipt"))
	}
	return token, nil
}

type PlatformClient struct {
	Endpoint NodeEndpoint
	HTTP     *http.Client
}

func NewPlatformClient(e NodeEndpoint) (*PlatformClient, error) {
	e = e.Defaults()
	c, err := e.Client()
	return &PlatformClient{e, c}, err
}
func (c *PlatformClient) Qualify(ctx context.Context, pool, registration, token string) (map[string]any, error) {
	if domain.ValidateIdentifier(pool) != nil || domain.ValidateIdentifier(registration) != nil || token == "" || len(token) > 16384 {
		return nil, domain.Err(409, "node_grant_unavailable")
	}
	b, e := boundedReply(ctx, c.HTTP, c.Endpoint, "POST", "/internal/nodes/v1/qualify", token, map[string]any{"node_id": c.Endpoint.NodeID, "pool_id": pool, "registration_id": registration}, c.Endpoint.MaxReplyBytes, false)
	if e != nil {
		return nil, e
	}
	var out map[string]any
	if strictDecode(b, &out) != nil || out["node_id"] != c.Endpoint.NodeID || out["pool_id"] != pool || out["registration_id"] != registration || out["healthy"] != true {
		return nil, domain.Err(409, "runtime_unhealthy")
	}
	profiles, ok := out["sandbox_profiles"].([]any)
	if !ok || !reflect.DeepEqual(profiles, []any{"runsc-cpu-v1"}) {
		return nil, domain.Err(409, "runtime_unhealthy")
	}
	capacity, ok := out["capacity"].(map[string]any)
	if !ok || len(capacity) != 3 {
		return nil, domain.Err(409, "runtime_unhealthy")
	}
	for _, k := range []string{"cpu_millicores", "memory_bytes", "disk_bytes"} {
		if number(capacity[k]) < 1 {
			return nil, domain.Err(409, "runtime_unhealthy")
		}
	}
	attestations, _ := out["profile_attestations"].(map[string]any)
	a, _ := attestations["runsc-cpu-v1"].(map[string]any)
	digest, _ := a["profile_sha256"].(string)
	if a["qualified"] != true || a["runtime"] != "runsc" || a["network"] != "none" || a["bounded_volumes"] != "loop-ext4" || !digestPattern.MatchString(digest) {
		return nil, domain.Err(409, "runtime_unhealthy")
	}
	return out, nil
}

func (r *RemoteExecutor) Route(ctx context.Context, id executor.ExecutionIdentity, pool string) (NodeRoute, error) {
	return r.config.Route(ctx, id, pool)
}
