package transfer

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

// OriginGrant remains entirely within trusted gateway/backend processes.
type OriginGrant struct {
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers"`
	ExpiresAt float64           `json:"expires_at"`
	Size      int64             `json:"size"`
	SHA256    string            `json:"sha256,omitempty"`
	Number    int               `json:"number,omitempty"`
}
type GatewayBackend interface {
	Authorize(context.Context, WorkloadIdentity) error
	UploadGrant(context.Context, WorkloadIdentity, string, string, string, int) (OriginGrant, error)
	BeginUpload(context.Context, WorkloadIdentity, string, string, string, int) (string, OriginGrant, error)
	FinishUpload(context.Context, WorkloadIdentity, string) (bool, error)
	DownloadGrant(context.Context, WorkloadIdentity, string, string, string) (OriginGrant, error)
}
type GatewaySettings struct {
	Verifier             WorkloadVerifier
	OriginEndpoints      []string
	OriginCAFile         string
	MaxPartBytes         int64
	MaxDownloadBytes     int64
	ChunkBytes           int
	Timeout              time.Duration
	AllowLocalOriginHTTP bool
	TrustedBackendSecret string
	// Client is injectable for deterministic transport tests. Production should
	// leave it nil so redirect, proxy and TLS policies are constructed here.
	Client *http.Client
}

func (s *GatewaySettings) defaults() error {
	if s.Verifier.Scope == "" {
		s.Verifier.Scope = "transfer"
	}
	if s.Verifier.Audience == "" {
		s.Verifier.Audience = "hf2l-transfer"
	}
	if err := s.Verifier.Validate(); err != nil {
		return err
	}
	if s.MaxPartBytes == 0 {
		s.MaxPartBytes = 64 << 20
	}
	if s.MaxDownloadBytes == 0 {
		s.MaxDownloadBytes = 1 << 40
	}
	if s.ChunkBytes == 0 {
		s.ChunkBytes = 65536
	}
	if s.Timeout == 0 {
		s.Timeout = 300 * time.Second
	}
	if len(s.OriginEndpoints) == 0 || s.MaxPartBytes < 1 || s.MaxDownloadBytes < 1 || s.ChunkBytes < 1024 || s.ChunkBytes > 1<<20 || s.Timeout <= 0 {
		return errors.New("explicit origin allowlist and positive bounded gateway limits required")
	}
	if s.TrustedBackendSecret != "" && len([]byte(s.TrustedBackendSecret)) < 32 {
		return errors.New("private backend secret must contain at least 32 bytes")
	}
	for _, origin := range s.OriginEndpoints {
		u, e := url.Parse(origin)
		if e != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("invalid private storage origin")
		}
		local := u.Hostname() == "127.0.0.1" || u.Hostname() == "::1" || u.Hostname() == "localhost"
		if u.Scheme != "https" && !(s.AllowLocalOriginHTTP && local && u.Scheme == "http") {
			return errors.New("storage origin requires HTTPS")
		}
	}
	return nil
}
func normalizedPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Port()
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}
func (s GatewaySettings) checkOrigin(grant OriginGrant) (string, http.Header, error) {
	if math.IsNaN(grant.ExpiresAt) || math.IsInf(grant.ExpiresAt, 0) || grant.URL == "" {
		return "", nil, domain.Err(502, "invalid_origin_descriptor")
	}
	u, e := url.Parse(grant.URL)
	if e != nil || u.User != nil || u.Fragment != "" || u.Hostname() == "" {
		return "", nil, domain.Err(502, "invalid_origin_descriptor")
	}
	if strings.Contains(u.Path, "\\") {
		return "", nil, domain.Err(502, "origin_not_allowed")
	}
	for _, p := range strings.Split(u.Path, "/") {
		if p == "." || p == ".." {
			return "", nil, domain.Err(502, "origin_not_allowed")
		}
	}
	for _, origin := range s.OriginEndpoints {
		allowed, _ := url.Parse(origin)
		if u.Scheme != allowed.Scheme || !strings.EqualFold(u.Hostname(), allowed.Hostname()) || normalizedPort(u) != normalizedPort(allowed) {
			continue
		}
		prefix := strings.TrimRight(allowed.Path, "/")
		if prefix != "" && u.Path != prefix && !strings.HasPrefix(u.Path, prefix+"/") {
			continue
		}
		if grant.ExpiresAt <= float64(s.Verifier.Clock().UnixNano())/1e9 {
			return "", nil, domain.Err(409, "origin_descriptor_expired")
		}
		out := http.Header{}
		for key, value := range grant.Headers {
			switch strings.ToLower(key) {
			case "content-type", "content-md5", "content-length", "x-amz-checksum-sha256":
			case "x-amz-content-sha256":
				// SDK-signed payload digests are required for empty S3 upload
				// parts. Accept only a concrete SHA-256, never unsigned or
				// streaming payload control values.
				if !digestRE.MatchString(value) {
					return "", nil, domain.Err(502, "invalid_origin_headers")
				}
			default:
				return "", nil, domain.Err(502, "invalid_origin_headers")
			}
			if strings.ContainsAny(value, "\r\n") {
				return "", nil, domain.Err(502, "invalid_origin_headers")
			}
			out.Set(key, value)
		}
		return grant.URL, out, nil
	}
	return "", nil, domain.Err(502, "origin_not_allowed")
}

var rangeRE = regexp.MustCompile("^bytes=([0-9]+)-([0-9]*)$")

type byteRange struct{ start, end int64 }

func downloadRange(value string, size int64) (*byteRange, error) {
	if value == "" {
		return nil, nil
	}
	m := rangeRE.FindStringSubmatch(value)
	if m == nil {
		return nil, domain.Err(416, "invalid_download_range")
	}
	start, e := strconv.ParseInt(m[1], 10, 64)
	if e != nil {
		return nil, domain.Err(416, "invalid_download_range")
	}
	end := size - 1
	if m[2] != "" {
		end, e = strconv.ParseInt(m[2], 10, 64)
		if e != nil {
			return nil, domain.Err(416, "invalid_download_range")
		}
	}
	if start < 0 || start > end || end >= size {
		return nil, domain.Err(416, "invalid_download_range")
	}
	return &byteRange{start, end}, nil
}

type Gateway struct {
	settings GatewaySettings
	backend  GatewayBackend
	client   *http.Client
}

func NewGateway(settings GatewaySettings, backend GatewayBackend) (http.Handler, error) {
	if backend == nil {
		return nil, errors.New("current Exchange ledger backend required")
	}
	if err := settings.defaults(); err != nil {
		return nil, err
	}
	client := settings.Client
	if client == nil {
		var err error
		client, err = newClient(settings.OriginCAFile, "", "", settings.Timeout)
		if err != nil {
			return nil, err
		}
	}
	return &Gateway{settings, backend, client}, nil
}

var gatewayRoute = regexp.MustCompile("^/transfers/v1/spaces/([^/]+)/records/([^/]+)/attachments/([^/]+)/(?:parts/([0-9]+)|(content))$")

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if unsafePath(r) {
		writeError(w, domain.Err(404, "operation_not_allowed"))
		return
	}
	m := gatewayRoute.FindStringSubmatch(r.URL.Path)
	if m == nil {
		writeError(w, domain.Err(404, "operation_not_allowed"))
		return
	}
	for _, v := range m[1:4] {
		if err := identifier(v); err != nil {
			writeError(w, err)
			return
		}
	}
	if r.URL.RawQuery != "" {
		writeError(w, domain.Err(400, "unexpected_transfer_query"))
		return
	}
	for _, name := range []string{"Cookie", "Proxy-Authorization", "X-Forwarded-Client-Cert"} {
		if _, ok := r.Header[http.CanonicalHeaderKey(name)]; ok {
			writeError(w, domain.Err(400, "forbidden_transfer_credentials"))
			return
		}
	}
	id, err := g.identity(r, m[1])
	if err != nil {
		writeError(w, err)
		return
	}
	if m[4] != "" && r.Method == http.MethodPut {
		number, err := strconv.Atoi(m[4])
		if err != nil || number < 1 || number > 10000 {
			writeError(w, domain.Err(422, "invalid_part_number"))
			return
		}
		g.upload(w, r, id, m[1], m[2], m[3], number)
		return
	}
	if m[5] != "" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		g.download(w, r, id, m[1], m[2], m[3])
		return
	}
	writeError(w, domain.Err(405, "method_not_allowed"))
}
func (g *Gateway) identity(r *http.Request, space string) (WorkloadIdentity, error) {
	thumb, err := verifiedThumbprint(r)
	if err != nil && g.settings.TrustedBackendSecret != "" {
		thumb, err = VerifiedBackendThumbprint(g.settings.TrustedBackendSecret, r.Method, requestTarget(r), r.Header.Get("Authorization"), r.Header, g.settings.Verifier.Clock())
	}
	if err != nil {
		return WorkloadIdentity{}, err
	}
	token, err := bearer(r.Header.Get("Authorization"))
	if err != nil {
		return WorkloadIdentity{}, err
	}
	id, err := g.settings.Verifier.Verify(token, thumb)
	if err != nil {
		return id, err
	}
	id.Token = token
	if id.SpaceID != space {
		return id, domain.Err(404, "resource_not_found")
	}
	err = g.backend.Authorize(r.Context(), id)
	return id, err
}
func (g *Gateway) recheck(ctx context.Context, id WorkloadIdentity) error {
	if _, e := g.settings.Verifier.Verify(id.Token, id.CertificateThumbprint); e != nil {
		return e
	}
	return g.backend.Authorize(ctx, id)
}

type checkedReader struct {
	source    io.ReadCloser
	remaining int64
	chunk     int
	check     func() error
	complete  atomic.Bool
}

func (r *checkedReader) Read(p []byte) (int, error) {
	if err := r.check(); err != nil {
		return 0, err
	}
	if r.remaining == 0 {
		r.complete.Store(true)
		return 0, io.EOF
	}
	if len(p) > r.chunk {
		p = p[:r.chunk]
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, e := r.source.Read(p)
	if n > 0 {
		if err := r.check(); err != nil {
			return 0, err
		}
	}
	r.remaining -= int64(n)
	if r.remaining == 0 {
		r.complete.Store(true)
	}
	if e == io.EOF && r.remaining != 0 {
		return n, io.ErrUnexpectedEOF
	}
	return n, e
}
func (r *checkedReader) Close() error { return r.source.Close() }
func (g *Gateway) upload(w http.ResponseWriter, r *http.Request, id WorkloadIdentity, space, record, attachment string, number int) {
	grant, err := g.backend.UploadGrant(r.Context(), id, space, record, attachment, number)
	if err != nil {
		writeError(w, err)
		return
	}
	expected := grant.Size
	if expected < 0 || expected > g.settings.MaxPartBytes {
		writeError(w, domain.Err(413, "part_too_large"))
		return
	}
	if r.ContentLength < 0 || r.Header.Get("Content-Length") == "" {
		writeError(w, domain.Err(411, "content_length_required"))
		return
	}
	if r.ContentLength != expected || len(r.TransferEncoding) > 0 {
		writeError(w, domain.Err(400, "part_size_mismatch"))
		return
	}
	if _, _, err = g.settings.checkOrigin(grant); err != nil {
		writeError(w, err)
		return
	}
	if err = g.recheck(r.Context(), id); err != nil {
		writeError(w, err)
		return
	}
	mutation, prepared, err := g.backend.BeginUpload(r.Context(), id, space, record, attachment, number)
	if err != nil {
		writeError(w, err)
		return
	}
	if mutation == "" || prepared.Size != expected {
		writeError(w, domain.Err(503, "invalid_origin_mutation_fence"))
		return
	}
	target, headers, err := g.settings.checkOrigin(prepared)
	if err != nil {
		writeError(w, err)
		return
	}
	headers.Del("Content-Length")
	headers.Set("Accept-Encoding", "identity")
	body := &checkedReader{source: r.Body, remaining: expected, chunk: g.settings.ChunkBytes, check: func() error { return g.recheck(r.Context(), id) }}
	if expected == 0 {
		body.complete.Store(true)
	}
	request, err := http.NewRequestWithContext(r.Context(), http.MethodPut, target, body)
	if err != nil {
		writeError(w, domain.Err(503, "origin_transfer_failed"))
		return
	}
	request.Header = headers
	request.ContentLength = expected
	if expected == 0 {
		request.Body = http.NoBody
	}
	response, err := g.client.Do(request)
	if err != nil {
		writeError(w, domain.Err(503, "origin_transfer_failed"))
		return
	}
	status := response.StatusCode
	etag := response.Header.Get("ETag")
	closeErr := response.Body.Close()
	if closeErr != nil || (status != 200 && status != 201 && status != 204) || !body.complete.Load() {
		writeError(w, domain.Err(503, "origin_transfer_failed"))
		return
	}
	// A failed/uncertain PUT deliberately leaves its durable mutation marker.
	settled, err := g.backend.FinishUpload(r.Context(), id, mutation)
	if err != nil {
		writeError(w, err)
		return
	}
	if !settled {
		writeError(w, domain.Err(503, "origin_mutation_not_settled"))
		return
	}
	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	w.WriteHeader(http.StatusNoContent)
}
func (g *Gateway) download(w http.ResponseWriter, r *http.Request, id WorkloadIdentity, space, record, attachment string) {
	grant, err := g.backend.DownloadGrant(r.Context(), id, space, record, attachment)
	if err != nil {
		writeError(w, err)
		return
	}
	if grant.Size < 0 || grant.Size > g.settings.MaxDownloadBytes || !digestRE.MatchString(grant.SHA256) {
		writeError(w, domain.Err(502, "invalid_origin_descriptor"))
		return
	}
	selected, err := downloadRange(r.Header.Get("Range"), grant.Size)
	if err != nil {
		writeError(w, err)
		return
	}
	count, status := grant.Size, http.StatusOK
	headers := http.Header{"Content-Type": {"application/octet-stream"}, "X-Content-Sha256": {grant.SHA256}, "Accept-Ranges": {"bytes"}, "Content-Disposition": {`attachment; filename="checkpoint.bin"`}, "X-Content-Type-Options": {"nosniff"}, "Cache-Control": {"no-store"}}
	if selected != nil {
		count = selected.end - selected.start + 1
		status = http.StatusPartialContent
		headers.Set("Content-Range", "bytes "+strconv.FormatInt(selected.start, 10)+"-"+strconv.FormatInt(selected.end, 10)+"/"+strconv.FormatInt(grant.Size, 10))
	}
	headers.Set("Content-Length", strconv.FormatInt(count, 10))
	if r.Method == http.MethodHead {
		copyHeaders(w.Header(), headers, safeResponseHeaders)
		w.WriteHeader(status)
		return
	}
	target, originHeaders, err := g.settings.checkOrigin(grant)
	if err != nil {
		writeError(w, err)
		return
	}
	originHeaders.Set("Accept-Encoding", "identity")
	if selected != nil {
		originHeaders.Set("Range", "bytes="+strconv.FormatInt(selected.start, 10)+"-"+strconv.FormatInt(selected.end, 10))
	}
	if err = g.recheck(r.Context(), id); err != nil {
		writeError(w, err)
		return
	}
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		writeError(w, domain.Err(503, "origin_transfer_failed"))
		return
	}
	request.Header = originHeaders
	upstream, err := g.client.Do(request)
	if err != nil {
		writeError(w, domain.Err(503, "origin_transfer_failed"))
		return
	}
	defer upstream.Body.Close()
	if upstream.StatusCode != status {
		writeError(w, domain.Err(503, "origin_transfer_failed"))
		return
	}
	if selected != nil && upstream.Header.Get("Content-Range") != headers.Get("Content-Range") {
		writeError(w, domain.Err(502, "invalid_origin_range"))
		return
	}
	if value := upstream.Header.Get("Content-Length"); value != "" && value != strconv.FormatInt(count, 10) {
		writeError(w, domain.Err(502, "invalid_origin_size"))
		return
	}
	copyHeaders(w.Header(), headers, safeResponseHeaders)
	w.WriteHeader(status)
	buf := make([]byte, g.settings.ChunkBytes)
	var total int64
	for {
		if g.recheck(r.Context(), id) != nil {
			return
		}
		n, e := upstream.Body.Read(buf)
		if n > 0 {
			if g.recheck(r.Context(), id) != nil {
				return
			}
			total += int64(n)
			if total > count {
				return
			}
			if _, err = w.Write(buf[:n]); err != nil {
				return
			}
			flush(w)
		}
		if e != nil {
			if e != io.EOF || total != count {
				return
			}
			return
		}
	}
}

func (g *Gateway) Close() error { g.client.CloseIdleConnections(); return nil }
