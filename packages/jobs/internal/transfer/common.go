// Package transfer implements credential-confining execution proxies and trusted
// certificate-authenticated Exchange transfer boundaries.
package transfer

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/certificates"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/golang-jwt/jwt/v5"
)

var identifierRE = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
var thumbprintRE = regexp.MustCompile("^[A-Za-z0-9_-]{43}$")
var digestRE = regexp.MustCompile("^[a-f0-9]{64}$")
var digitsRE = regexp.MustCompile("^[0-9]+$")

func identifier(s string) error {
	if !identifierRE.MatchString(s) {
		return domain.Err(422, "invalid_resource_identifier")
	}
	return nil
}
func CertificateThumbprint(der []byte) string {
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type ExecutionIdentity struct {
	JobID       string `json:"job_id"`
	AttemptID   string `json:"attempt_id"`
	ComponentID string `json:"component_id"`
	Epoch       int64  `json:"epoch"`
}

func (id ExecutionIdentity) Validate() error {
	for _, s := range []string{id.JobID, id.AttemptID, id.ComponentID} {
		if err := identifier(s); err != nil {
			return err
		}
	}
	if id.Epoch < 1 {
		return domain.Err(422, "invalid_execution_binding")
	}
	return nil
}
func (id ExecutionIdentity) Key() string {
	raw, _ := domain.CanonicalJSON(map[string]any{"job_id": id.JobID, "attempt_id": id.AttemptID, "component_id": id.ComponentID, "epoch": id.Epoch})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:32]
}

type ExecutionBinding struct {
	JobID                 string `json:"job_id"`
	AttemptID             string `json:"attempt_id"`
	ComponentID           string `json:"component_id"`
	SpaceID               string `json:"space_id"`
	Epoch                 int64  `json:"epoch"`
	CertificateThumbprint string `json:"certificate_thumbprint"`
}

func (b ExecutionBinding) Identity() ExecutionIdentity {
	return ExecutionIdentity{b.JobID, b.AttemptID, b.ComponentID, b.Epoch}
}
func (b ExecutionBinding) Validate() error {
	if err := b.Identity().Validate(); err != nil {
		return err
	}
	if err := identifier(b.SpaceID); err != nil {
		return err
	}
	if !thumbprintRE.MatchString(b.CertificateThumbprint) {
		return domain.Err(422, "invalid_execution_binding")
	}
	return nil
}

type WorkloadIdentity struct {
	ExecutionBinding
	GrantID     string
	PrincipalID string
	Subject     string
	Token       string `json:"-"`
	ExpiresAt   time.Time
}
type WorkloadVerifier struct {
	Issuer    string
	Audience  string
	Scope     string
	PublicKey string
	Clock     func() time.Time
	key       *rsa.PublicKey
}

func (v *WorkloadVerifier) Validate() error {
	if v.Issuer == "" || v.Audience == "" || v.Scope == "" {
		return errors.New("fixed workload issuer, audience and scope are required")
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(v.PublicKey))
	if err != nil {
		return errors.New("invalid workload verification key")
	}
	v.key = key
	if v.Clock == nil {
		v.Clock = time.Now
	}
	return nil
}
func jsonInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	x, e := n.Int64()
	return x, e == nil
}
func jsonFloat(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	x, e := n.Float64()
	return x, e == nil
}
func (v *WorkloadVerifier) Verify(token, thumb string) (WorkloadIdentity, error) {
	var out WorkloadIdentity
	invalid := func() (WorkloadIdentity, error) { return out, domain.Err(401, "invalid_workload_token") }
	if v.key == nil || !thumbprintRE.MatchString(thumb) {
		return invalid()
	}
	claims := jwt.MapClaims{}
	t, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodRS256 || t.Header["typ"] != "at+jwt" || t.Header["jku"] != nil || t.Header["x5u"] != nil {
			return nil, errors.New("invalid JWT header")
		}
		return v.key, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(v.Issuer), jwt.WithAudience(v.Audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithJSONNumber(), jwt.WithTimeFunc(v.Clock))
	if err != nil || !t.Valid {
		return invalid()
	}
	if claims["aud"] != v.Audience {
		return invalid()
	}
	for key, limit := range map[string]int{"sub": 256, "jti": 64, "space_id": 64, "job_id": 128, "attempt_id": 128, "component_id": 128} {
		value, ok := claims[key].(string)
		if !ok || utf8.RuneCountInString(value) < 1 || utf8.RuneCountInString(value) > limit {
			return invalid()
		}
	}
	epoch, ok := jsonInt(claims["epoch"])
	if !ok || epoch < 1 {
		return invalid()
	}
	exp, eok := jsonFloat(claims["exp"])
	iat, iok := jsonFloat(claims["iat"])
	if !eok || !iok || exp-iat <= 0 || exp-iat > 300 {
		return invalid()
	}
	cnf, ok := claims["cnf"].(map[string]any)
	if !ok || len(cnf) != 1 || cnf["x5t#S256"] != thumb {
		return invalid()
	}
	jti := claims["jti"].(string)
	if gid, exists := claims["grant_id"]; exists && gid != jti {
		return invalid()
	}
	scope, ok := claims["scope"].(string)
	if !ok {
		return invalid()
	}
	found := false
	for _, s := range strings.Fields(scope) {
		if s == v.Scope {
			found = true
		}
	}
	if !found {
		return invalid()
	}
	out = WorkloadIdentity{ExecutionBinding: ExecutionBinding{JobID: claims["job_id"].(string), AttemptID: claims["attempt_id"].(string), ComponentID: claims["component_id"].(string), SpaceID: claims["space_id"].(string), Epoch: epoch, CertificateThumbprint: thumb}, GrantID: jti, Subject: claims["sub"].(string), ExpiresAt: time.Unix(int64(exp), int64((exp-float64(int64(exp)))*1e9))}
	out.PrincipalID = domain.PrincipalID(v.Issuer, out.Subject)
	if out.Validate() != nil {
		return invalid()
	}
	return out, nil
}
func bearer(header string) (string, error) {
	p := strings.SplitN(header, " ", 2)
	if len(p) != 2 || !strings.EqualFold(p[0], "bearer") || p[1] == "" {
		return "", domain.Err(401, "invalid_workload_token")
	}
	return p[1], nil
}
func verifiedThumbprint(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return "", domain.Err(401, "verified_tls_required")
	}
	leaf := r.TLS.PeerCertificates[0]
	found := false
	for _, chain := range r.TLS.VerifiedChains {
		if len(chain) > 0 && bytes.Equal(chain[0].Raw, leaf.Raw) {
			found = true
		}
	}
	if !found {
		return "", domain.Err(401, "verified_tls_required")
	}
	return CertificateThumbprint(leaf.Raw), nil
}
func asciiQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString("\\\"")
		case '\\':
			b.WriteString("\\\\")
		case '\b':
			b.WriteString("\\b")
		case '\f':
			b.WriteString("\\f")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			if r < 32 || r >= 127 {
				if r <= 65535 {
					fmt.Fprintf(&b, "\\u%04x", r)
				} else {
					r -= 65536
					fmt.Fprintf(&b, "\\u%04x\\u%04x", 0xd800+(r>>10), 0xdc00+(r&1023))
				}
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
func BackendAssertionHeaders(secret, method, target, authorization, thumb string, stamp time.Time) (http.Header, error) {
	if len([]byte(secret)) < 32 || !thumbprintRE.MatchString(thumb) {
		return nil, errors.New("invalid trusted backend configuration")
	}
	timestamp := strconv.FormatInt(stamp.Unix(), 10)
	values := []string{strings.ToUpper(method), target, authorization, thumb, timestamp}
	encoded := make([]string, len(values))
	for i, s := range values {
		encoded[i] = asciiQuote(s)
	}
	message := "[" + strings.Join(encoded, ",") + "]"
	h := hmac.New(sha256.New, []byte(secret))
	_, _ = h.Write([]byte(message))
	out := http.Header{}
	out.Set("X-HF2L-Backend-Timestamp", timestamp)
	out.Set("X-HF2L-TLS-Thumbprint", thumb)
	out.Set("X-HF2L-Backend-Signature", hex.EncodeToString(h.Sum(nil)))
	return out, nil
}
func VerifiedBackendThumbprint(secret, method, target, authorization string, headers http.Header, now time.Time) (string, error) {
	invalid := func() (string, error) { return "", domain.Err(401, "invalid_backend_assertion") }
	timestamp := headers.Get("X-HF2L-Backend-Timestamp")
	thumb := headers.Get("X-HF2L-TLS-Thumbprint")
	if !digitsRE.MatchString(timestamp) {
		return invalid()
	}
	stamp, e := strconv.ParseInt(timestamp, 10, 64)
	if e != nil {
		return invalid()
	}
	d := now.Sub(time.Unix(stamp, 0))
	if d > 30*time.Second || d < -30*time.Second {
		return invalid()
	}
	expected, e := BackendAssertionHeaders(secret, method, target, authorization, thumb, time.Unix(stamp, 0))
	if e != nil {
		return invalid()
	}
	got := headers.Get("X-HF2L-Backend-Signature")
	if !digestRE.MatchString(got) || !hmac.Equal([]byte(got), []byte(expected.Get("X-HF2L-Backend-Signature"))) {
		return invalid()
	}
	return thumb, nil
}
func serviceEndpoint(value string) (string, error) {
	u, e := url.Parse(value)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("service endpoint must be a fixed HTTPS origin")
	}
	return strings.TrimRight(value, "/"), nil
}
func tlsConfig(caFile, certFile, keyFile string) (*tls.Config, error) {
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if caFile != "" {
		data, e := certificates.ReadTrustBundleFile(caFile)
		if e != nil {
			return nil, e
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			return nil, errors.New("invalid TLS trust file")
		}
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	if (certFile == "") != (keyFile == "") {
		return nil, errors.New("client certificate and private key must be configured together")
	}
	if certFile != "" {
		certificatePEM, e := certificates.ReadPEMFile(certFile, false)
		if e != nil {
			return nil, e
		}
		privatePEM, e := certificates.ReadPEMFile(keyFile, true)
		if e != nil {
			return nil, e
		}
		pair, e := tls.X509KeyPair(certificatePEM, privatePEM)
		if e != nil {
			return nil, e
		}
		cfg.Certificates = []tls.Certificate{pair}
	}

	return cfg, nil
}
func newClient(caFile, certFile, keyFile string, timeout time.Duration) (*http.Client, error) {
	cfg, e := tlsConfig(caFile, certFile, keyFile)
	if e != nil {
		return nil, e
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.TLSClientConfig = cfg
	t.DisableCompression = true
	t.MaxIdleConnsPerHost = 16
	t.ResponseHeaderTimeout = timeout
	return &http.Client{Transport: t, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
func certFromPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}
func writeError(w http.ResponseWriter, err error) {
	status, code := 500, "transfer_failed"
	var d *domain.Error
	if errors.As(err, &d) {
		status, code = d.Status, d.Code
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code}})
}
func requestTarget(r *http.Request) string {
	p := r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		p += "?" + r.URL.RawQuery
	}
	return p
}
func unsafePath(r *http.Request) bool {
	p := r.URL.EscapedPath()
	if r.URL.IsAbs() || !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "%\\") || strings.Contains(p, "//") {
		return true
	}
	for _, x := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if x == "" || x == "." || x == ".." {
			return true
		}
	}
	return false
}
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > limit {
		return nil, domain.Err(413, "request_too_large")
	}
	return b, nil
}
func copyHeaders(dst, src http.Header, allowed map[string]bool) {
	for k, v := range src {
		if allowed[strings.ToLower(k)] {
			dst[k] = append([]string(nil), v...)
		}
	}
}

var safeRequestHeaders = map[string]bool{"accept": true, "content-type": true, "content-length": true, "idempotency-key": true, "if-match": true, "if-none-match": true, "range": true}
var safeResponseHeaders = map[string]bool{"content-type": true, "content-length": true, "etag": true, "retry-after": true, "content-range": true, "accept-ranges": true, "x-content-sha256": true, "content-disposition": true, "x-content-type-options": true, "cache-control": true}

func flush(w http.ResponseWriter) {
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}
func contextError(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// MTLSSettings configures an independently verified private TLS listener.
type MTLSSettings struct {
	Address, Certificate, Key, ClientCA string
	MaxRequestBytes                     int64
}

func NewMTLSServer(s MTLSSettings, h http.Handler) (*http.Server, net.Listener, error) {
	if s.Address == "" {
		s.Address = "127.0.0.1:0"
	}
	if s.MaxRequestBytes == 0 {
		s.MaxRequestBytes = 64 << 20
	}
	if s.MaxRequestBytes < 1 {
		return nil, nil, errors.New("positive request limit required")
	}
	pair, e := tls.LoadX509KeyPair(s.Certificate, s.Key)
	if e != nil {
		return nil, nil, e
	}
	pem, e := os.ReadFile(s.ClientCA)
	if e != nil {
		return nil, nil, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, nil, errors.New("invalid client trust file")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, Certificates: []tls.Certificate{pair}}
	listener, e := net.Listen("tcp", s.Address)
	if e != nil {
		return nil, nil, e
	}
	slots := make(chan struct{}, 64)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			writeError(w, domain.Err(503, "service_busy"))
			return
		}
		if _, e := verifiedThumbprint(r); e != nil {
			writeError(w, e)
			return
		}
		if r.ContentLength < 0 || r.ContentLength > s.MaxRequestBytes || len(r.TransferEncoding) > 0 {
			writeError(w, domain.Err(413, "request_too_large"))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, s.MaxRequestBytes)
		h.ServeHTTP(w, r)
	})
	server := &http.Server{Handler: handler, TLSConfig: config, ReadHeaderTimeout: 30 * time.Second, ReadTimeout: 300 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 65536}
	return server, tls.NewListener(limitConnections(listener, 64), config), nil
}

// limitedListener bounds accepted connections before TLS handshakes allocate
// per-connection work. Handler semaphores alone do not bound slow handshakes.
type limitedListener struct {
	net.Listener
	slots chan struct{}
	done  chan struct{}
	once  sync.Once
}

func limitConnections(listener net.Listener, count int) net.Listener {
	return &limitedListener{Listener: listener, slots: make(chan struct{}, count), done: make(chan struct{})}
}
func (l *limitedListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, net.ErrClosed
	case l.slots <- struct{}{}:
	}
	conn, e := l.Listener.Accept()
	if e != nil {
		<-l.slots
		return nil, e
	}
	return &limitedConnection{Conn: conn, release: func() { <-l.slots }}, nil
}
func (l *limitedListener) Close() error {
	var e error
	l.once.Do(func() { close(l.done); e = l.Listener.Close() })
	return e
}

type limitedConnection struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *limitedConnection) Close() error {
	e := c.Conn.Close()
	c.once.Do(c.release)
	return e
}
