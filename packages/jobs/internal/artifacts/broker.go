//go:build linux

package artifacts

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"hash"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"crypto/sha256"
	"encoding/hex"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/certificates"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/exchange"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
	"golang.org/x/sys/unix"
)

type Download struct {
	Name        string
	Size        int64
	ContentType string
	Reader      io.ReadCloser
}

func (d *Download) Close() error {
	if d == nil || d.Reader == nil {
		return nil
	}
	return d.Reader.Close()
}

type ArtifactManager interface {
	ArtifactStorage(context.Context, string, string, string) (map[string]any, error)
	GetArtifact(context.Context, string, string, string) (map[string]any, error)
	GetJob(context.Context, string, string) (map[string]any, error)
}
type GatewayDownloadBackend interface {
	Open(context.Context, string, map[string]any, map[string]any) (io.ReadCloser, error)
	Revoke(context.Context, string) (bool, error)
}
type BrokerConfig struct {
	Root, ExecutorRoot string
	MaxBytes           int64
	Gateway            GatewayDownloadBackend
	RemoteRoute        func(context.Context, LogIdentity) (string, error)
	RemoteRead         func(context.Context, LogIdentity, string, int64) ([]byte, error)
}
type Broker struct {
	manager ArtifactManager
	db      *store.DB
	config  BrokerConfig
}

func NewBroker(manager ArtifactManager, db *store.DB, cfg BrokerConfig) (*Broker, error) {
	if manager == nil || db == nil {
		return nil, domain.Err(422, "invalid_artifact_broker")
	}
	if _, e := absoluteParts(cfg.Root); e != nil {
		return nil, e
	}
	if cfg.ExecutorRoot != "" {
		if _, e := absoluteParts(cfg.ExecutorRoot); e != nil {
			return nil, e
		}
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = 1 << 40
	}
	if cfg.MaxBytes < 1 {
		return nil, domain.Err(422, "invalid_artifact_bound")
	}
	return &Broker{manager, db, cfg}, nil
}
func ArtifactAttemptID(jobID string) string { return "artifact-" + digest([]byte(jobID))[:40] }
func (b *Broker) resource(ctx context.Context, jobID, resourceID string) (map[string]any, error) {
	row, e := b.db.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id = ?", resourceID)
	if e != nil {
		return nil, e
	}
	if row == nil || text(row["job_id"]) != jobID || row["deleted_at"] != nil || text(row["state"]) == "deleted" || text(row["state"]) == "cleanup_pending" || text(row["external_id"]) == "" || text(mapping(row["ownership_json"])["job_id"]) != jobID {
		return nil, domain.Err(404, "artifact_unavailable")
	}
	return row, nil
}
func (b *Broker) OpenAuthorized(ctx context.Context, actor, jobID, artifactID string) (*Download, error) {
	meta, e := b.manager.ArtifactStorage(ctx, actor, jobID, artifactID)
	if e != nil {
		return nil, e
	}
	size := integer(meta["size_bytes"])
	if size < 0 || size > b.config.MaxBytes {
		return nil, domain.Err(413, "artifact_too_large")
	}
	sha := text(meta["sha256"])
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(sha) {
		return nil, domain.Err(409, "invalid_artifact_descriptor")
	}
	raw, e := domain.CanonicalJSON(meta["locator"])
	if e != nil {
		return nil, domain.Err(404, "artifact_unavailable")
	}
	parsed, e := domain.DecodeArtifactLocator(raw)
	if e != nil {
		return nil, domain.Err(404, "artifact_unavailable")
	}
	locator := parsed.Map()
	var reader io.ReadCloser
	var closeCheck func() error
	recheck := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		current, e := b.manager.GetArtifact(ctx, actor, jobID, artifactID)
		if e != nil {
			return e
		}
		if available, exists := current["download_available"]; exists && !flag(available) {
			return domain.Err(410, "artifact_unavailable")
		}
		if amount, exists := current["size_bytes"]; exists && integer(amount) != size {
			return domain.Err(409, "artifact_descriptor_mismatch")
		}
		if hash, exists := current["sha256"]; exists && text(hash) != sha {
			return domain.Err(409, "artifact_descriptor_mismatch")
		}
		return nil
	}
	if text(locator["kind"]) == "exchange" {
		if b.config.Gateway == nil {
			return nil, domain.Err(503, "artifact_broker_unavailable")
		}
		reader, e = b.config.Gateway.Open(ctx, jobID, meta, locator)
	} else {
		resource, e2 := b.resource(ctx, jobID, text(locator["resource_id"]))
		if e2 != nil {
			return nil, e2
		}
		external := text(resource["external_id"])
		if strings.HasPrefix(external, "hf2l-node://") {
			reader, e = b.openRemote(ctx, jobID, meta, locator, resource)
		} else {
			reader, closeCheck, e = b.openLocal(ctx, jobID, meta, locator, resource)
		}
		prior := recheck
		recheck = func() error {
			if e := prior(); e != nil {
				return e
			}
			_, e := b.resource(ctx, jobID, text(locator["resource_id"]))
			return e
		}
	}
	if e != nil {
		return nil, e
	}
	safeName := text(meta["name"])
	if safeName == "" || strings.ContainsAny(safeName, "/\\\r\n\x00") {
		safeName = "artifact.bin"
	}
	checked := &integrityReader{source: reader, digest: sha256.New(), size: size, expected: sha, check: recheck, final: closeCheck}
	return &Download{Name: safeName, Size: size, ContentType: "application/octet-stream", Reader: checked}, nil
}
func (b *Broker) openLocal(ctx context.Context, jobID string, meta, locator, resource map[string]any) (io.ReadCloser, func() error, error) {
	root := text(resource["external_id"])
	expectedRoot := filepath.Join(b.config.Root, jobID)
	kind := text(resource["kind"])
	own := mapping(resource["ownership_json"])
	if kind == "retained_artifact_root" {
		identity := LogIdentity{jobID, text(own["attempt_id"]), text(own["component_id"]), integer(own["epoch"])}
		if e := identity.Validate(); e != nil {
			return nil, nil, domain.Err(404, "artifact_unavailable")
		}
		if b.config.ExecutorRoot == "" {
			return nil, nil, domain.Err(404, "artifact_unavailable")
		}
		parent := filepath.Join(b.config.ExecutorRoot, identity.Key(), "retained")
		allowed := root == filepath.Join(parent, "state") || root == filepath.Join(parent, "runtime")
		path := text(locator["relative_path"])
		allowed = allowed || (root == parent && (strings.HasPrefix(path, "state/") || strings.HasPrefix(path, "runtime/")))
		if !allowed {
			return nil, nil, domain.Err(404, "artifact_unavailable")
		}
	} else {
		switch kind {
		case "artifact_directory", "component_state", "component_volume", "source", "source_snapshot", "source_directory", "owned_directory":
			if root != expectedRoot && !strings.HasPrefix(root, expectedRoot+string(os.PathSeparator)) {
				return nil, nil, domain.Err(404, "artifact_unavailable")
			}
		default:
			return nil, nil, domain.Err(404, "artifact_unavailable")
		}
	}
	size := integer(meta["size_bytes"])
	maximum := size
	if maximum < 1 {
		maximum = 1
	}
	collector, e := NewCollector(root, CollectorOptions{MaxFileBytes: maximum, MaxTotalBytes: maximum})
	if e != nil {
		return nil, nil, domain.Err(404, "artifact_unavailable")
	}
	collector.mu.RLock()
	file, before, e := collector.openFile(text(locator["relative_path"]), maximum)
	collector.mu.RUnlock()
	if e != nil {
		collector.Close()
		return nil, nil, domain.Err(404, "artifact_unavailable")
	}
	if before.Size != size {
		file.Close()
		collector.Close()
		return nil, nil, domain.Err(409, "artifact_descriptor_mismatch")
	}
	final := func() error {
		var after unix.Stat_t
		if e := unix.Fstat(int(file.Fd()), &after); e != nil {
			return domain.Err(502, "artifact_changed")
		}
		if e := collector.validateFile(int(file.Fd()), &after); e != nil || !sameFile(before, after) {
			return domain.Err(502, "artifact_changed")
		}
		return nil
	}
	return &joinedCloser{Reader: file, close: func() error { e := file.Close(); collector.Close(); return e }}, final, nil
}
func (b *Broker) openRemote(ctx context.Context, jobID string, meta, locator, resource map[string]any) (io.ReadCloser, error) {
	own := mapping(resource["ownership_json"])
	identity := LogIdentity{jobID, text(own["attempt_id"]), text(own["component_id"]), integer(own["epoch"])}
	if e := identity.Validate(); e != nil {
		return nil, domain.Err(404, "artifact_unavailable")
	}
	u, e := url.Parse(text(resource["external_id"]))
	details := mapping(resource["details_json"])
	if e != nil || text(resource["kind"]) != "retained_artifact_root" || u.Scheme != "hf2l-node" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/"+identity.Key() || u.RawPath != "" || text(details["node_id"]) != u.Host || b.config.RemoteRoute == nil || b.config.RemoteRead == nil {
		return nil, domain.Err(404, "artifact_unavailable")
	}
	node, e := b.config.RemoteRoute(ctx, identity)
	if e != nil || node != u.Host {
		return nil, domain.Err(404, "artifact_unavailable")
	}
	size := integer(meta["size_bytes"])
	if size > 64<<20 {
		return nil, domain.Err(413, "remote_artifact_too_large")
	}
	max := size
	if max < 1 {
		max = 1
	}
	raw, e := b.config.RemoteRead(ctx, identity, text(locator["relative_path"]), max)
	if e != nil {
		return nil, e
	}
	if int64(len(raw)) != size || digest(raw) != text(meta["sha256"]) {
		return nil, domain.Err(409, "artifact_integrity_failed")
	}
	return io.NopCloser(bytes.NewReader(raw)), nil
}
func (b *Broker) Revoke(ctx context.Context, jobID string) (bool, error) {
	if b.config.Gateway == nil {
		owned, e := b.db.One(ctx, "SELECT id FROM jm_provisioning_resources WHERE job_id = ? AND kind = ? AND deleted_at IS NULL", jobID, "exchange_space")
		if e != nil {
			return false, e
		}
		if owned != nil {
			return false, domain.Err(503, "artifact_broker_unavailable")
		}
		return true, nil
	}
	return b.config.Gateway.Revoke(ctx, jobID)
}

type joinedCloser struct {
	io.Reader
	close func() error
}

func (r *joinedCloser) Close() error { return r.close() }

type integrityReader struct {
	source           io.ReadCloser
	digest           hash.Hash
	size, count      int64
	expected         string
	check, final     func() error
	finished, closed bool
}

func (r *integrityReader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, os.ErrClosed
	}
	if r.finished {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.check != nil {
		if e := r.check(); e != nil {
			return 0, e
		}
	}
	if len(p) > 65536 {
		p = p[:65536]
	}
	n, e := r.source.Read(p)
	if n > 0 {
		r.count += int64(n)
		if r.count > r.size {
			return 0, domain.Err(502, "artifact_descriptor_mismatch")
		}
		r.digest.Write(p[:n])
	}
	if errors.Is(e, io.EOF) {
		r.finished = true
		if r.count != r.size || hex.EncodeToString(r.digest.Sum(nil)) != r.expected {
			return 0, domain.Err(502, "artifact_integrity_failed")
		}
		if r.final != nil {
			if err := r.final(); err != nil {
				return 0, err
			}
		}
	}
	return n, e
}
func (r *integrityReader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	return r.source.Close()
}

// ManagedGatewayBackend creates invocation-private, read-only job grants and
// keeps certificate private keys in memory. It never returns an origin URL.
type ManagedGatewayConfig struct {
	Endpoint, CAFile string
	CAPEM            []byte
	MaxBytes         int64
	Exchange         *exchange.Client
	Workloads        *exchange.Broker
	Certificates     *certificates.Issuer
	Clock            func() time.Time
}
type ManagedGatewayBackend struct {
	DB       *store.DB
	config   ManagedGatewayConfig
	endpoint string
	roots    *x509.CertPool
}

func NewManagedGatewayBackend(db *store.DB, cfg ManagedGatewayConfig) (*ManagedGatewayBackend, error) {
	endpoint, e := exchange.ServiceEndpoint(cfg.Endpoint, false)
	if e != nil {
		return nil, e
	}
	if db == nil || cfg.Exchange == nil || cfg.Workloads == nil || cfg.Certificates == nil {
		return nil, domain.Err(422, "invalid_artifact_broker")
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = 1 << 40
	}
	if cfg.MaxBytes < 1 {
		return nil, domain.Err(422, "invalid_artifact_bound")
	}
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	raw := cfg.CAPEM
	if cfg.CAFile != "" {
		if len(raw) > 0 {
			return nil, domain.Err(422, "ambiguous_service_trust")
		}
		raw, e = certificates.ReadPEMFile(cfg.CAFile, false)
		if e != nil {
			return nil, e
		}
	}
	if len(raw) > 0 {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(raw) {
			return nil, domain.Err(422, "invalid_service_trust")
		}
	}
	return &ManagedGatewayBackend{db, cfg, endpoint, roots}, nil
}
func (g *ManagedGatewayBackend) now() time.Time {
	if g.config.Clock != nil {
		return g.config.Clock().UTC()
	}
	return time.Now().UTC()
}
func (g *ManagedGatewayBackend) ownedSpace(ctx context.Context, jobID, spaceID string) error {
	row, e := g.DB.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE job_id = ? AND kind = ? AND external_id = ? AND deleted_at IS NULL", jobID, "exchange_space", spaceID)
	if e != nil {
		return e
	}
	if row == nil || text(row["state"]) == "deleted" || text(row["state"]) == "cleanup_pending" || text(mapping(row["ownership_json"])["job_id"]) != jobID {
		return domain.Err(404, "artifact_unavailable")
	}
	return nil
}
func (g *ManagedGatewayBackend) grant(ctx context.Context, jobID, spaceID, requestID, thumbprint string, expiry float64) (map[string]any, error) {
	if e := g.ownedSpace(ctx, jobID, spaceID); e != nil {
		return nil, e
	}
	component := "download-broker"
	subject, e := exchange.StableWorkloadSubject(jobID, component, nil)
	if e != nil {
		return nil, e
	}
	principal, e := exchange.StableWorkloadPrincipal(g.config.Workloads.Issuer(), jobID, component, nil)
	if e != nil {
		return nil, e
	}
	if _, e = g.config.Exchange.SetMember(ctx, spaceID, principal, []string{"reader"}, &subject, map[string]any{}); e != nil {
		return nil, e
	}
	body := map[string]any{"subject": subject, "job_id": jobID, "attempt_id": ArtifactAttemptID(jobID), "component_id": component, "epoch": int64(1), "certificate_thumbprint": thumbprint, "expires_at": expiry, "roles": []string{"reader"}, "bindings": map[string]any{}}
	path, e := exchange.Path(spaceID, "/workload-grants")
	if e != nil {
		return nil, e
	}
	grant, e := g.config.Exchange.Request(ctx, "POST", path, body, map[string]string{"Idempotency-Key": "artifact-" + requestID}, nil)
	if e != nil {
		return nil, e
	}
	if text(grant["principal_id"]) != principal || text(grant["job_id"]) != jobID || text(grant["space_id"]) != spaceID || domain.ValidateIdentifier(text(grant["grant_id"])) != nil {
		return nil, domain.Err(503, "invalid_broker_grant")
	}
	e = g.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id = ?"+tx.ForUpdate(), jobID)
		if e != nil {
			return e
		}
		if job == nil || logsExpired(job, g.now()) {
			return domain.Err(410, "artifact_unavailable")
		}
		own := map[string]any{"job_id": jobID, "component_id": component, "kind": "workload_grant"}
		previous, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE kind = ? AND external_id = ?", "workload_grant", grant["grant_id"])
		if e != nil {
			return e
		}
		if previous != nil {
			if !sameJSON(previous["ownership_json"], own) {
				return domain.Err(409, "resource_ownership_mismatch")
			}
			return nil
		}
		return tx.Insert(ctx, "jm_provisioning_resources", map[string]any{"id": domain.NewID(), "job_id": jobID, "attempt_id": nil, "component_id": component, "kind": "workload_grant", "external_id": grant["grant_id"], "ownership_json": own, "details_json": grant, "state": "owned", "retained": true, "size_bytes": int64(0), "created_at": g.now(), "updated_at": g.now()})
	})
	if e != nil {
		return nil, e
	}
	return grant, nil
}
func (g *ManagedGatewayBackend) Open(ctx context.Context, jobID string, metadata, locator map[string]any) (io.ReadCloser, error) {
	space, record, attachment := text(locator["space_id"]), text(locator["record_id"]), text(locator["attachment_id"])
	for _, id := range []string{space, record, attachment} {
		if e := domain.ValidateIdentifier(id); e != nil {
			return nil, domain.Err(422, "invalid_artifact_locator")
		}
	}
	if e := g.ownedSpace(ctx, jobID, space); e != nil {
		return nil, e
	}
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return nil, domain.Err(503, "broker_certificate_unavailable")
	}
	csrDER, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if e != nil {
		return nil, e
	}
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	issued, e := g.config.Certificates.Issue(csr, certificates.Binding{JobID: jobID, AttemptID: ArtifactAttemptID(jobID), ComponentID: "download-broker", SpaceID: space, Epoch: 1}, g.now().Add(300*time.Second))
	if e != nil {
		return nil, e
	}
	if issued.ExpiresAt > float64(g.now().UnixNano())/1e9+301 {
		return nil, domain.Err(503, "broker_certificate_lifetime_exceeds_bound")
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, e
	}
	pair, e := tls.X509KeyPair([]byte(issued.CertificatePEM), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	if e != nil {
		return nil, e
	}
	grant, e := g.grant(ctx, jobID, space, domain.NewID(), issued.CertificateThumbprint, issued.ExpiresAt)
	if e != nil {
		return nil, e
	}
	remaining := int64(math.Floor(issued.ExpiresAt - float64(g.now().UnixNano())/1e9))
	if remaining < 1 {
		return nil, domain.Err(401, "broker_grant_expired")
	}
	if remaining > g.config.Workloads.MaxTTL() {
		remaining = g.config.Workloads.MaxTTL()
	}
	token, e := g.config.Workloads.IssueWorkload(exchange.WorkloadRequest{JobID: jobID, AttemptID: ArtifactAttemptID(jobID), ComponentID: "download-broker", SpaceID: space, GrantID: text(grant["grant_id"]), CertificateThumbprint: issued.CertificateThumbprint, Audience: "gateway", Epoch: 1, TTLSeconds: remaining})
	if e != nil {
		return nil, e
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: g.roots, Certificates: []tls.Certificate{pair}}, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second, DisableCompression: true}
	client := &http.Client{Transport: transport, Timeout: 300 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	target := g.endpoint + "/transfers/v1/spaces/" + space + "/records/" + record + "/attachments/" + attachment + "/content"
	request, e := http.NewRequestWithContext(ctx, "GET", target, nil)
	if e != nil {
		transport.CloseIdleConnections()
		return nil, e
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, e := client.Do(request)
	if e != nil {
		transport.CloseIdleConnections()
		return nil, domain.Err(503, "artifact_unavailable")
	}
	fail := func(err error) (io.ReadCloser, error) {
		response.Body.Close()
		transport.CloseIdleConnections()
		return nil, err
	}
	if response.StatusCode != 200 {
		status := response.StatusCode
		if status >= 500 {
			status = 503
		}
		return fail(domain.Err(status, "artifact_unavailable"))
	}
	size, e := strconv.ParseInt(response.Header.Get("Content-Length"), 10, 64)
	if e != nil || size < 0 {
		return fail(domain.Err(502, "invalid_artifact_descriptor"))
	}
	if size > g.config.MaxBytes {
		return fail(domain.Err(413, "artifact_too_large"))
	}
	if size != integer(metadata["size_bytes"]) || response.Header.Get("X-Content-SHA256") != text(metadata["sha256"]) {
		return fail(domain.Err(409, "artifact_descriptor_mismatch"))
	}
	body := &joinedCloser{Reader: response.Body, close: func() error { e := response.Body.Close(); transport.CloseIdleConnections(); return e }}
	return &integrityReader{source: body, digest: sha256.New(), size: size, expected: text(metadata["sha256"])}, nil
}
func (g *ManagedGatewayBackend) Revoke(ctx context.Context, jobID string) (bool, error) {
	row, e := g.DB.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE job_id = ? AND kind = ? AND deleted_at IS NULL", jobID, "exchange_space")
	if e != nil {
		return false, e
	}
	if row == nil {
		return true, nil
	}
	if text(mapping(row["ownership_json"])["job_id"]) != jobID {
		return false, domain.Err(409, "resource_ownership_mismatch")
	}
	path, e := exchange.Path(text(row["external_id"]), "/workload-grants/revoke")
	if e != nil {
		return false, e
	}
	result, e := g.config.Exchange.Request(ctx, "POST", path, map[string]any{"attempt_id": ArtifactAttemptID(jobID)}, map[string]string{"Idempotency-Key": "artifact-revoke-" + jobID}, nil)
	if e != nil {
		return false, e
	}
	return text(result["attempt_id"]) == ArtifactAttemptID(jobID) && result["revoked_at"] != nil, nil
}
