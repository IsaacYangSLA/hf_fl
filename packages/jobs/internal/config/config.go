// Package config validates trusted deployment configuration without executing job code.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/exchange"
	"io"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
)

const MaxConfigBytes int64 = 1048576

var Sections = map[string]bool{"executor": true, "node": true, "provisioner": true, "service": true, "gateway": true, "proxy": true, "retention": true, "boundaries": true, "controller": true, "secrets": true, "nodes": true, "participants": true}

type Error struct{ Code string }

func (e *Error) Error() string { return e.Code }
func Invalid() error           { return &Error{Code: "invalid_deployment_configuration"} }

type OIDCSettings struct {
	Issuer           string
	ClientID         string
	ClientSecret     string
	RedirectURI      string
	Audience         string
	IntrospectionURL string
	JWKSURL          string
	PublicKey        string
	EndpointOrigins  []string
	TimeoutSeconds   float64
	JWKSCacheSeconds int
	AllowLocalHTTP   bool
}
type WorkloadSettings struct {
	Issuer, ExchangeAudience, GatewayAudience, NodeAudience, PrivateKey, PublicKey, KeyID string
}
type Settings struct {
	DatabaseURL                    string
	CursorSecret                   string
	SessionSecret                  string
	OIDC                           OIDCSettings
	Workload                       *WorkloadSettings
	PlatformOperatorIDs            []string
	MaxBodyBytes                   int64
	DocsEnabled                    bool
	Extra                          map[string]any
	GracefulShutdownTimeoutSeconds int
}

// String deliberately excludes credentials and operational configuration.
func (s Settings) String() string         { return "job manager settings (private)" }
func (s OIDCSettings) String() string     { return "OIDC settings (private)" }
func (s WorkloadSettings) String() string { return "workload settings (private)" }

func RequireTLS(raw string, allowLocal bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return Invalid()
	}
	if u.Scheme == "https" {
		return nil
	}
	h := strings.ToLower(u.Hostname())
	ip := net.ParseIP(h)
	local := h == "localhost" || h == "testserver" || ip != nil && ip.IsLoopback()
	if u.Scheme == "http" && allowLocal && local {
		return nil
	}
	return Invalid()
}
func Origin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
		return "", Invalid()
	}
	return u.Scheme + "://" + strings.ToLower(u.Host), nil
}
func (o OIDCSettings) ValidateEndpoint(raw string) error {
	if err := RequireTLS(raw, o.AllowLocalHTTP); err != nil {
		return err
	}
	actual, _ := Origin(raw)
	issuer, _ := Origin(o.Issuer)
	if actual == issuer {
		return nil
	}
	for _, allowed := range o.EndpointOrigins {
		if actual == allowed {
			return nil
		}
	}
	return Invalid()
}
func (o OIDCSettings) Validate() error {
	if o.Issuer == "" || o.ClientID == "" || o.RedirectURI == "" || o.Audience == "" {
		return Invalid()
	}
	if err := RequireTLS(o.Issuer, o.AllowLocalHTTP); err != nil {
		return err
	}
	if err := RequireTLS(o.RedirectURI, o.AllowLocalHTTP); err != nil {
		return err
	}
	i, _ := url.Parse(o.Issuer)
	c, _ := url.Parse(o.RedirectURI)
	if i.RawQuery != "" || c.RawQuery != "" || c.Fragment != "" {
		return Invalid()
	}
	for _, raw := range o.EndpointOrigins {
		if err := RequireTLS(raw, o.AllowLocalHTTP); err != nil {
			return err
		}
		u, _ := url.Parse(raw)
		origin, _ := Origin(raw)
		if raw != origin || u.Path != "" || u.RawQuery != "" {
			return Invalid()
		}
	}
	for _, raw := range []string{o.IntrospectionURL, o.JWKSURL} {
		if raw != "" {
			if err := o.ValidateEndpoint(raw); err != nil {
				return err
			}
		}
	}
	if o.PublicKey != "" && o.JWKSURL != "" {
		return Invalid()
	}
	if math.IsNaN(o.TimeoutSeconds) || math.IsInf(o.TimeoutSeconds, 0) || o.TimeoutSeconds <= 0 || o.TimeoutSeconds > 30 || o.JWKSCacheSeconds < 1 || o.JWKSCacheSeconds > 300 {
		return Invalid()
	}
	return nil
}
func (s Settings) Validate(component string) error {
	if !strings.HasPrefix(s.DatabaseURL, "postgresql:") && !strings.HasPrefix(s.DatabaseURL, "postgresql+psycopg:") && !strings.HasPrefix(s.DatabaseURL, "sqlite:") {
		return Invalid()
	}
	if math.IsNaN(s.OIDC.TimeoutSeconds) || math.IsInf(s.OIDC.TimeoutSeconds, 0) {
		return Invalid()
	}
	if s.GracefulShutdownTimeoutSeconds < 1 || s.GracefulShutdownTimeoutSeconds > 60 || s.MaxBodyBytes < 1024 || s.MaxBodyBytes > 8388608 {
		return Invalid()
	}
	if component == "server" {
		if err := s.OIDC.Validate(); err != nil {
			return err
		}
		if len([]byte(s.CursorSecret)) < 32 || len([]byte(s.SessionSecret)) < 32 || s.CursorSecret == s.SessionSecret {
			return Invalid()
		}
	}
	if s.Workload != nil {
		w := s.Workload
		if w.Issuer == "" || w.PublicKey == "" || w.ExchangeAudience == "" || w.GatewayAudience == "" || w.NodeAudience == "" {
			return Invalid()
		}
		if _, e := exchange.NewBroker(exchange.BrokerSettings{Issuer: w.Issuer, ExchangeAudience: w.ExchangeAudience, GatewayAudience: w.GatewayAudience, NodeAudience: w.NodeAudience, KeyID: w.KeyID, PublicKeyPEM: []byte(w.PublicKey), PrivateKeyPEM: []byte(w.PrivateKey)}); e != nil {
			return Invalid()
		}
	}
	for name, value := range s.Extra {
		if !Sections[name] {
			return Invalid()
		}
		if _, ok := value.(map[string]any); !ok {
			return Invalid()
		}
	}
	return nil
}

type Lookup func(string) (string, bool)

func Env(lookup Lookup, name, def string) (string, error) {
	a, aok := lookup("JOBS_" + name)
	b, bok := lookup("HF2L_JOBS_" + name)
	if aok && bok && a != b {
		return "", Invalid()
	}
	if aok {
		return a, nil
	}
	if bok {
		return b, nil
	}
	return def, nil
}
func split(raw string) []string {
	out := []string{}
	for _, s := range strings.Split(raw, ",") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
func Load(path, component string) (Settings, error) { return FromEnv(os.LookupEnv, path, component) }
func FromEnv(lookup Lookup, path, component string) (Settings, error) {
	var first error
	get := func(name, def string) string {
		v, e := Env(lookup, name, def)
		if e != nil && first == nil {
			first = e
		}
		return v
	}
	integer := func(name, def string) int64 {
		v, e := strconv.ParseInt(strings.TrimSpace(get(name, def)), 10, 64)
		if e != nil && first == nil {
			first = Invalid()
		}
		return v
	}
	boolean := func(name string, def bool) bool {
		raw := strings.ToLower(get(name, strconv.FormatBool(def)))
		switch raw {
		case "true", "1":
			return true
		case "false", "0":
			return false
		}
		if first == nil {
			first = Invalid()
		}
		return false
	}
	secret := func(name string) string {
		p := get(name, "")
		if p == "" {
			return ""
		}
		v, e := ReadSecret(p)
		if e != nil && first == nil {
			first = e
		}
		return v
	}
	public := func(name string) string {
		p := get(name, "")
		if p == "" {
			return ""
		}
		v, e := ReadFile(p, 65536, false)
		if e != nil && first == nil {
			first = e
		}
		return string(v)
	}
	allow := boolean("ALLOW_LOCAL_HTTP", false)
	timeout, e := strconv.ParseFloat(get("OIDC_TIMEOUT_SECONDS", "5"), 64)
	if e != nil {
		first = Invalid()
	}
	s := Settings{
		DatabaseURL:  get("DATABASE_URL", "postgresql+psycopg://localhost/hf2l_jobs"),
		CursorSecret: secret("CURSOR_SECRET_FILE"), SessionSecret: secret("SESSION_SECRET_FILE"),
		OIDC:                OIDCSettings{Issuer: get("OIDC_ISSUER", ""), ClientID: get("OIDC_CLIENT_ID", ""), ClientSecret: secret("OIDC_CLIENT_SECRET_FILE"), RedirectURI: get("OIDC_REDIRECT_URI", ""), Audience: get("AUDIENCE", "hf2l-jobs"), IntrospectionURL: get("OIDC_INTROSPECTION_URL", ""), JWKSURL: get("OIDC_JWKS_URL", ""), PublicKey: public("OIDC_PUBLIC_KEY_FILE"), EndpointOrigins: split(get("OIDC_ENDPOINT_ORIGINS", "")), TimeoutSeconds: timeout, JWKSCacheSeconds: int(integer("OIDC_JWKS_CACHE_SECONDS", "300")), AllowLocalHTTP: allow},
		PlatformOperatorIDs: split(get("PLATFORM_OPERATOR_IDS", "")), MaxBodyBytes: integer("MAX_BODY_BYTES", "1048576"), DocsEnabled: boolean("DOCS_ENABLED", false), Extra: map[string]any{}, GracefulShutdownTimeoutSeconds: int(integer("GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS", "15")),
	}
	if s.CursorSecret == "" {
		s.CursorSecret = get("CURSOR_SECRET", "")
	}
	if s.SessionSecret == "" {
		s.SessionSecret = get("SESSION_SECRET", "")
	}
	if s.OIDC.ClientSecret == "" {
		s.OIDC.ClientSecret = get("OIDC_CLIENT_SECRET", "")
	}
	if issuer := get("WORKLOAD_ISSUER", ""); issuer != "" {
		s.Workload = &WorkloadSettings{Issuer: issuer, ExchangeAudience: get("WORKLOAD_EXCHANGE_AUDIENCE", "exchange-managed"), GatewayAudience: get("WORKLOAD_GATEWAY_AUDIENCE", "hf2l-transfer"), NodeAudience: get("NODE_AUDIENCE", "hf2l-nodes"), PrivateKey: secret("WORKLOAD_PRIVATE_KEY_FILE"), PublicKey: public("WORKLOAD_PUBLIC_KEY_FILE"), KeyID: get("WORKLOAD_KEY_ID", "")}
	}
	envpath := get("OPERATIONAL_CONFIG_FILE", "")
	if envpath == "" {
		envpath = get("CONFIG", "")
	}
	if path == "" {
		path = envpath
	}
	if first != nil {
		return Settings{}, first
	}
	if path != "" {
		extra, err := ReadJSON(path, MaxConfigBytes)
		if err != nil {
			return Settings{}, err
		}
		s.Extra = extra
	}
	if err := s.Validate(component); err != nil {
		return Settings{}, err
	}
	return s, nil
}

// ReadFile walks every directory with O_NOFOLLOW and validates the opened inode.
func ReadFile(path string, limit int64, private bool) ([]byte, error) {
	if limit < 1 {
		return nil, Invalid()
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, Invalid()
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(abs), string(filepath.Separator)), string(filepath.Separator))
	if len(parts) == 0 || parts[0] == "" {
		return nil, Invalid()
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, Invalid()
	}
	for _, part := range parts[:len(parts)-1] {
		next, e := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		syscall.Close(fd)
		if e != nil {
			return nil, Invalid()
		}
		fd = next
	}
	filefd, err := syscall.Openat(fd, parts[len(parts)-1], syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	syscall.Close(fd)
	if err != nil {
		return nil, Invalid()
	}
	f := os.NewFile(uintptr(filefd), abs)
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(filefd, &st); err != nil {
		return nil, Invalid()
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Nlink != 1 || st.Size < 0 || st.Size > limit || st.Mode&0022 != 0 {
		return nil, Invalid()
	}
	if private && (st.Mode&0077 != 0 || st.Size < 1) {
		return nil, Invalid()
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit || !utf8.Valid(data) {
		return nil, Invalid()
	}
	var after syscall.Stat_t
	if syscall.Fstat(filefd, &after) != nil || after.Dev != st.Dev || after.Ino != st.Ino || after.Size != st.Size || after.Mtim != st.Mtim || int64(len(data)) != after.Size {
		return nil, Invalid()
	}
	return data, nil
}
func ReadSecret(path string) (string, error) {
	b, e := ReadFile(path, 65536, true)
	if e != nil {
		return "", e
	}
	return strings.TrimSpace(string(b)), nil
}
func decodeValue(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, Invalid()
	}
	tok, err := d.Token()
	if err != nil {
		return nil, Invalid()
	}
	if delim, ok := tok.(json.Delim); ok {
		if delim == '{' {
			out := map[string]any{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return nil, Invalid()
				}
				s, ok := key.(string)
				if !ok {
					return nil, Invalid()
				}
				if _, exists := out[s]; exists {
					return nil, Invalid()
				}
				v, e := decodeValue(d, depth+1)
				if e != nil {
					return nil, e
				}
				out[s] = v
			}
			if end, e := d.Token(); e != nil || end != json.Delim('}') {
				return nil, Invalid()
			}
			return out, nil
		}
		if delim == '[' {
			out := []any{}
			for d.More() {
				v, e := decodeValue(d, depth+1)
				if e != nil {
					return nil, e
				}
				out = append(out, v)
			}
			if end, e := d.Token(); e != nil || end != json.Delim(']') {
				return nil, Invalid()
			}
			return out, nil
		}
		return nil, Invalid()
	}
	return tok, nil
}
func DecodeJSON(data []byte) (map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	v, e := decodeValue(d, 0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); !errors.Is(e, io.EOF) {
		return nil, Invalid()
	}
	result, ok := v.(map[string]any)
	if !ok {
		return nil, Invalid()
	}
	return result, nil
}
func ReadJSON(path string, limit int64) (map[string]any, error) {
	b, e := ReadFile(path, limit, false)
	if e != nil {
		return nil, e
	}
	return DecodeJSON(b)
}
func (s Settings) Section(name string, required bool) (map[string]any, error) {
	v, ok := s.Extra[name]
	if !ok && !required {
		return map[string]any{}, nil
	}
	m, ok := v.(map[string]any)
	if !ok || required && len(m) == 0 {
		return nil, Invalid()
	}
	return m, nil
}
func Keys(m map[string]any, required, optional []string) error {
	allowed := map[string]bool{}
	for _, k := range required {
		allowed[k] = true
		if _, ok := m[k]; !ok {
			return Invalid()
		}
	}
	for _, k := range optional {
		allowed[k] = true
	}
	for k := range m {
		if !allowed[k] {
			return Invalid()
		}
	}
	return nil
}
func Text(v any, max int) (string, error) {
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" || utf8.RuneCountInString(s) > max {
		return "", Invalid()
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return "", Invalid()
		}
	}
	return s, nil
}
func Int(v any, min, max int64) (int64, error) {
	var n int64
	switch x := v.(type) {
	case json.Number:
		if strings.ContainsAny(string(x), ".eE") {
			return 0, Invalid()
		}
		var e error
		n, e = x.Int64()
		if e != nil {
			return 0, Invalid()
		}
	case int:
		n = int64(x)
	case int64:
		n = x
	default:
		return 0, Invalid()
	}
	if n < min || n > max {
		return 0, Invalid()
	}
	return n, nil
}
func Bool(v any) (bool, error) {
	b, ok := v.(bool)
	if !ok {
		return false, Invalid()
	}
	return b, nil
}
func GetString(m map[string]any, key, def string) (string, error) {
	v, ok := m[key]
	if !ok {
		return def, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", Invalid()
	}
	return s, nil
}
func GetInt(m map[string]any, key string, def, min, max int64) (int64, error) {
	v, ok := m[key]
	if !ok {
		return def, nil
	}
	return Int(v, min, max)
}
func GetBool(m map[string]any, key string, def bool) (bool, error) {
	v, ok := m[key]
	if !ok {
		return def, nil
	}
	return Bool(v)
}
func DecodeSection(m map[string]any, target any) error {
	b, e := json.Marshal(m)
	if e != nil {
		return Invalid()
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(target); e != nil {
		return Invalid()
	}
	return nil
}
