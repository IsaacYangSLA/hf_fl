package exchange

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/golang-jwt/jwt/v5"
)

type NodeValidator func(context.Context, NodePrincipal) (bool, error)
type RegistrationValidator func(context.Context, PlatformNodePrincipal) (bool, error)
type BrokerSettings struct {
	Issuer, ExchangeAudience, GatewayAudience, NodeAudience, KeyID string
	PublicKeyPEM, PrivateKeyPEM                                    []byte
	MaxTTLSeconds                                                  int64
	Clock                                                          func() time.Time
	NodeGrantValidator                                             NodeValidator
	NodeRegistrationValidator                                      RegistrationValidator
}
type Broker struct {
	settings BrokerSettings
	public   *rsa.PublicKey
	private  *rsa.PrivateKey
	clock    func() time.Time
}

func (b *Broker) String() string { return "<WorkloadBroker fixed trusted signing identity>" }
func (b *Broker) Issuer() string { return b.settings.Issuer }
func (b *Broker) MaxTTL() int64  { return b.settings.MaxTTLSeconds }
func (b *Broker) Audience(which string) (string, error) {
	switch which {
	case "exchange":
		return b.settings.ExchangeAudience, nil
	case "gateway":
		return b.settings.GatewayAudience, nil
	case "node":
		return b.settings.NodeAudience, nil
	}
	return "", domain.Err(422, "invalid_workload_audience")
}
func NewBroker(cfg BrokerSettings) (*Broker, error) {
	for _, s := range []string{cfg.Issuer, cfg.ExchangeAudience, cfg.GatewayAudience, cfg.NodeAudience} {
		if s == "" || len([]rune(s)) > 2048 {
			return nil, domain.Err(422, "invalid_broker_configuration")
		}
		for _, c := range s {
			if c < 33 {
				return nil, domain.Err(422, "invalid_broker_configuration")
			}
		}
	}
	if cfg.ExchangeAudience == cfg.GatewayAudience || cfg.ExchangeAudience == cfg.NodeAudience || cfg.GatewayAudience == cfg.NodeAudience {
		return nil, domain.Err(422, "invalid_broker_configuration")
	}
	if cfg.MaxTTLSeconds == 0 {
		cfg.MaxTTLSeconds = 300
	}
	if cfg.MaxTTLSeconds < 1 || cfg.MaxTTLSeconds > 300 || cfg.KeyID != "" && !validIdentifier(cfg.KeyID) {
		return nil, domain.Err(422, "invalid_broker_configuration")
	}
	if len(cfg.PublicKeyPEM) == 0 || len(cfg.PublicKeyPEM) > 65536 {
		return nil, domain.Err(422, "invalid_broker_key")
	}
	public, e := jwt.ParseRSAPublicKeyFromPEM(cfg.PublicKeyPEM)
	if e != nil || public.N.BitLen() < 2048 {
		return nil, domain.Err(422, "invalid_broker_key")
	}
	var private *rsa.PrivateKey
	if len(cfg.PrivateKeyPEM) > 0 {
		if len(cfg.PrivateKeyPEM) > 65536 {
			return nil, domain.Err(422, "invalid_broker_key")
		}
		private, e = jwt.ParseRSAPrivateKeyFromPEM(cfg.PrivateKeyPEM)
		if e != nil || private.N.BitLen() < 2048 || public.E != private.E || public.N.Cmp(private.N) != 0 {
			return nil, domain.Err(422, "invalid_broker_key")
		}
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	// Retain no raw PEM copies after parsing.
	cfg.PublicKeyPEM = nil
	cfg.PrivateKeyPEM = nil
	return &Broker{cfg, public, private, clock}, nil
}
func validIdentifier(s string) bool { return domain.ValidateIdentifier(s) == nil }
func checkedID(s string) error {
	if !validIdentifier(s) {
		return domain.Err(422, "invalid_credential_binding")
	}
	return nil
}
func validThumbprint(s string) bool {
	if len(s) != 43 {
		return false
	}
	p, e := base64.RawURLEncoding.DecodeString(s)
	return e == nil && len(p) == 32 && base64.RawURLEncoding.EncodeToString(p) == s
}
func StableWorkloadSubject(job, component string, participant *string) (string, error) {
	if checkedID(job) != nil || checkedID(component) != nil || participant != nil && checkedID(*participant) != nil {
		return "", domain.Err(422, "invalid_credential_binding")
	}
	var p any
	if participant != nil {
		p = *participant
	}
	// Identifiers are ASCII, so this compact encoding equals Python ensure_ascii=True.
	b, _ := json.Marshal([]any{job, component, p})
	sum := sha256.Sum256(b)
	return "job:" + hex.EncodeToString(sum[:]), nil
}
func StableWorkloadPrincipal(issuer, job, component string, participant *string) (string, error) {
	sub, e := StableWorkloadSubject(job, component, participant)
	if e != nil {
		return "", e
	}
	return domain.PrincipalID(issuer, sub), nil
}

type WorkloadRequest struct {
	JobID, AttemptID, ComponentID, SpaceID, GrantID, CertificateThumbprint, Audience string
	Epoch, TTLSeconds                                                                int64
	ParticipantID                                                                    *string
}
type WorkloadPrincipal struct {
	ID, Subject, JobID, AttemptID, ComponentID, SpaceID, GrantID, CertificateThumbprint, Audience string
	Epoch, IssuedAt, ExpiresAt                                                                    int64
	ParticipantID                                                                                 *string
}
type NodeRequest struct {
	NodeID, PoolID, JobID, AttemptID, ComponentID, GrantID, CertificateThumbprint string
	Epoch, TTLSeconds                                                             int64
	Scopes                                                                        []string
	Resources                                                                     map[string]any
}
type NodePrincipal struct {
	ID, Subject, NodeID, PoolID, JobID, AttemptID, ComponentID, GrantID, CertificateThumbprint string
	Epoch, IssuedAt, ExpiresAt                                                                 int64
	Scopes                                                                                     []string
	Resources                                                                                  map[string]any
}

func (p NodePrincipal) HasScope(scope string) bool {
	for _, s := range p.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

type PlatformNodeRequest struct {
	NodeID, PoolID, RegistrationID, CertificateThumbprint string
	TTLSeconds                                            int64
}
type PlatformNodePrincipal struct {
	ID, Subject, NodeID, PoolID, RegistrationID, CertificateThumbprint string
	Scopes                                                             []string
	ExpiresAt                                                          int64
}

func (p PlatformNodePrincipal) HasScope(scope string) bool {
	for _, s := range p.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

var nodeScopes = map[string]bool{"acknowledge": true, "heartbeat": true, "progress": true, "logs": true, "stopped": true, "collect": true, "reserve": true, "start": true, "inspect": true, "stop": true, "release": true, "renew": true, "assignment": true, "purge": true}

func (b *Broker) base(subject, audience, grant, thumb string, ttl int64) (jwt.MapClaims, error) {
	if ttl == 0 {
		ttl = 300
	}
	if ttl < 1 || ttl > b.settings.MaxTTLSeconds {
		return nil, domain.Err(422, "invalid_credential_lifetime")
	}
	if checkedID(grant) != nil {
		return nil, domain.Err(422, "invalid_credential_binding")
	}
	if !validThumbprint(thumb) {
		return nil, domain.Err(422, "invalid_certificate_binding")
	}
	now := b.clock().Unix()
	return jwt.MapClaims{"iss": b.settings.Issuer, "aud": audience, "sub": subject, "iat": now, "nbf": now, "exp": now + ttl, "jti": grant, "grant_id": grant, "cnf": map[string]any{"x5t#S256": thumb}}, nil
}
func (b *Broker) sign(claims jwt.MapClaims) (string, error) {
	if b.private == nil {
		return "", domain.Err(503, "signing_key_unavailable")
	}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["typ"] = "at+jwt"
	if b.settings.KeyID != "" {
		t.Header["kid"] = b.settings.KeyID
	}
	v, e := t.SignedString(b.private)
	if e != nil {
		return "", domain.Err(503, "signing_key_unavailable")
	}
	return v, nil
}
func (b *Broker) IssueWorkload(req WorkloadRequest) (string, error) {
	if req.Audience == "" {
		req.Audience = "exchange"
	}
	audience, e := b.Audience(req.Audience)
	if e != nil || req.Audience == "node" {
		return "", domain.Err(422, "invalid_workload_audience")
	}
	for _, id := range []string{req.JobID, req.AttemptID, req.ComponentID, req.SpaceID} {
		if e := checkedID(id); e != nil {
			return "", e
		}
	}
	if req.Epoch < 1 {
		return "", domain.Err(422, "invalid_credential_epoch")
	}
	sub, e := StableWorkloadSubject(req.JobID, req.ComponentID, req.ParticipantID)
	if e != nil {
		return "", e
	}
	c, e := b.base(sub, audience, req.GrantID, req.CertificateThumbprint, req.TTLSeconds)
	if e != nil {
		return "", e
	}
	scope := "exchange"
	if req.Audience == "gateway" {
		scope = "transfer"
	}
	c["token_use"] = "workload"
	c["scope"] = scope
	c["job_id"] = req.JobID
	c["attempt_id"] = req.AttemptID
	c["component_id"] = req.ComponentID
	c["space_id"] = req.SpaceID
	c["epoch"] = req.Epoch
	if req.ParticipantID != nil {
		c["participant_id"] = *req.ParticipantID
	}
	return b.sign(c)
}
func intValue(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case int32:
		return int64(n), true
	case json.Number:
		x, e := n.Int64()
		return x, e == nil
	default:
		return 0, false
	}
}
func resourceLimits(input map[string]any) (map[string]any, error) {
	out := map[string]any{}
	for k, v := range input {
		switch k {
		case "cpu_millicores", "memory_bytes", "disk_bytes":
			n, ok := intValue(v)
			if !ok || n < 1 || n > 1<<50 {
				return nil, domain.Err(422, "invalid_node_resources")
			}
			out[k] = n
		case "gpu_uuids":
			var values []string
			switch a := v.(type) {
			case []string:
				values = append([]string{}, a...)
			case []any:
				for _, x := range a {
					s, ok := x.(string)
					if !ok {
						return nil, domain.Err(422, "invalid_node_resources")
					}
					values = append(values, s)
				}
			default:
				return nil, domain.Err(422, "invalid_node_resources")
			}
			if len(values) > 1024 {
				return nil, domain.Err(422, "invalid_node_resources")
			}
			seen := map[string]bool{}
			for _, s := range values {
				if !validIdentifier(s) || seen[s] {
					return nil, domain.Err(422, "invalid_node_resources")
				}
				seen[s] = true
			}
			out[k] = values
		default:
			return nil, domain.Err(422, "invalid_node_resources")
		}
	}
	return out, nil
}
func normalizedScopes(input []string, dedupe bool) ([]string, error) {
	if len(input) == 0 {
		return nil, domain.Err(422, "invalid_node_scopes")
	}
	seen := map[string]bool{}
	for _, s := range input {
		if !nodeScopes[s] || !dedupe && seen[s] {
			return nil, domain.Err(422, "invalid_node_scopes")
		}
		seen[s] = true
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}
func needsResources(scopes []string) bool {
	for _, s := range scopes {
		if s == "reserve" || s == "start" || s == "renew" {
			return true
		}
	}
	return false
}
func (b *Broker) IssueNode(req NodeRequest) (string, error) {
	for _, s := range []string{req.NodeID, req.PoolID, req.JobID, req.AttemptID, req.ComponentID} {
		if e := checkedID(s); e != nil {
			return "", e
		}
	}
	if req.Epoch < 1 {
		return "", domain.Err(422, "invalid_credential_epoch")
	}
	scopes, e := normalizedScopes(req.Scopes, true)
	if e != nil {
		return "", e
	}
	resources, e := resourceLimits(req.Resources)
	if e != nil {
		return "", e
	}
	if needsResources(scopes) {
		for _, k := range []string{"cpu_millicores", "memory_bytes", "disk_bytes"} {
			if _, ok := resources[k]; !ok {
				return "", domain.Err(422, "invalid_node_resources")
			}
		}
	}
	c, e := b.base("node:"+req.NodeID, b.settings.NodeAudience, req.GrantID, req.CertificateThumbprint, req.TTLSeconds)
	if e != nil {
		return "", e
	}
	c["token_use"] = "node"
	c["scope"] = strings.Join(scopes, " ")
	c["node_id"] = req.NodeID
	c["pool_id"] = req.PoolID
	c["job_id"] = req.JobID
	c["attempt_id"] = req.AttemptID
	c["component_id"] = req.ComponentID
	c["epoch"] = req.Epoch
	c["resources"] = resources
	return b.sign(c)
}
func (b *Broker) IssueNodePlatform(req PlatformNodeRequest) (string, error) {
	if checkedID(req.NodeID) != nil || checkedID(req.PoolID) != nil || checkedID(req.RegistrationID) != nil {
		return "", domain.Err(422, "invalid_credential_binding")
	}
	c, e := b.base("node-platform:"+req.NodeID, b.settings.NodeAudience, req.RegistrationID, req.CertificateThumbprint, req.TTLSeconds)
	if e != nil {
		return "", e
	}
	delete(c, "grant_id")
	c["token_use"] = "node_platform"
	c["scope"] = "qualify"
	c["node_id"] = req.NodeID
	c["pool_id"] = req.PoolID
	c["registration_id"] = req.RegistrationID
	return b.sign(c)
}
func (b *Broker) IssuePlatformNode(req PlatformNodeRequest) (string, error) {
	return b.IssueNodePlatform(req)
}
func invalidToken() error { return domain.Err(401, "invalid_access_token") }
func (b *Broker) decode(authorization, audience, peer string, jobBound bool) (jwt.MapClaims, error) {
	if len(authorization) > 16384 {
		return nil, invalidToken()
	}
	pieces := strings.SplitN(authorization, " ", 2)
	if len(pieces) != 2 || !strings.EqualFold(pieces[0], "bearer") || pieces[1] == "" {
		return nil, invalidToken()
	}
	for _, c := range pieces[1] {
		if unicode.IsSpace(c) {
			return nil, invalidToken()
		}
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithJSONNumber(), jwt.WithoutClaimsValidation())
	tok, e := parser.Parse(pieces[1], func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != "RS256" || t.Header["typ"] != "at+jwt" {
			return nil, invalidToken()
		}
		for k := range t.Header {
			if k != "alg" && k != "typ" && k != "kid" {
				return nil, invalidToken()
			}
		}
		if b.settings.KeyID != "" && t.Header["kid"] != b.settings.KeyID {
			return nil, invalidToken()
		}
		return b.public, nil
	})
	if e != nil || tok == nil || !tok.Valid {
		return nil, invalidToken()
	}
	c, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, invalidToken()
	}
	if c["iss"] != b.settings.Issuer || c["aud"] != audience {
		return nil, invalidToken()
	}
	sub, ok := c["sub"].(string)
	if !ok || sub == "" || len([]rune(sub)) > 256 {
		return nil, invalidToken()
	}
	iat, ok := intValue(c["iat"])
	if !ok {
		return nil, invalidToken()
	}
	nbf, ok := intValue(c["nbf"])
	if !ok {
		return nil, invalidToken()
	}
	exp, ok := intValue(c["exp"])
	if !ok {
		return nil, invalidToken()
	}
	now := b.clock().Unix()
	if nbf != iat || iat > now || exp <= iat || exp-iat > b.settings.MaxTTLSeconds || exp <= now {
		return nil, invalidToken()
	}
	grant, ok := c["jti"].(string)
	if !ok || !validIdentifier(grant) {
		return nil, invalidToken()
	}
	if g, present := c["grant_id"]; present && g != grant {
		return nil, invalidToken()
	}
	cnf, ok := c["cnf"].(map[string]any)
	if !ok || len(cnf) != 1 {
		return nil, invalidToken()
	}
	thumb, ok := cnf["x5t#S256"].(string)
	if !ok || !validThumbprint(thumb) || !validThumbprint(peer) || subtle.ConstantTimeCompare([]byte(thumb), []byte(peer)) != 1 {
		return nil, invalidToken()
	}
	if jobBound {
		for _, k := range []string{"job_id", "attempt_id", "component_id"} {
			s, ok := c[k].(string)
			if !ok || !validIdentifier(s) {
				return nil, invalidToken()
			}
		}
		epoch, ok := intValue(c["epoch"])
		if !ok || epoch < 1 {
			return nil, invalidToken()
		}
	}
	return c, nil
}
func claimString(c jwt.MapClaims, k string) string { v, _ := c[k].(string); return v }
func claimInt(c jwt.MapClaims, k string) int64     { v, _ := intValue(c[k]); return v }
func claimThumb(c jwt.MapClaims) string {
	v, _ := c["cnf"].(map[string]any)["x5t#S256"].(string)
	return v
}
func (b *Broker) AuthenticateWorkload(authorization, peer, audience string) (WorkloadPrincipal, error) {
	fail := WorkloadPrincipal{}
	fixed, e := b.Audience(audience)
	if e != nil || audience == "node" {
		return fail, invalidToken()
	}
	c, e := b.decode(authorization, fixed, peer, true)
	if e != nil {
		return fail, e
	}
	scope := "exchange"
	if audience == "gateway" {
		scope = "transfer"
	}
	if c["token_use"] != "workload" || c["scope"] != scope || !validIdentifier(claimString(c, "space_id")) {
		return fail, invalidToken()
	}
	var participant *string
	if p, exists := c["participant_id"]; exists {
		v, ok := p.(string)
		if !ok || !validIdentifier(v) {
			return fail, invalidToken()
		}
		participant = &v
	}
	subject, e := StableWorkloadSubject(claimString(c, "job_id"), claimString(c, "component_id"), participant)
	if e != nil || subject != claimString(c, "sub") {
		return fail, invalidToken()
	}
	return WorkloadPrincipal{domain.PrincipalID(b.settings.Issuer, subject), subject, claimString(c, "job_id"), claimString(c, "attempt_id"), claimString(c, "component_id"), claimString(c, "space_id"), claimString(c, "jti"), claimThumb(c), fixed, claimInt(c, "epoch"), claimInt(c, "iat"), claimInt(c, "exp"), participant}, nil
}
func (b *Broker) AuthenticateNode(ctx context.Context, authorization, peer string, validator NodeValidator) (NodePrincipal, error) {
	fail := NodePrincipal{}
	c, e := b.decode(authorization, b.settings.NodeAudience, peer, true)
	if e != nil {
		return fail, e
	}
	node, pool := claimString(c, "node_id"), claimString(c, "pool_id")
	if c["token_use"] != "node" || !validIdentifier(node) || !validIdentifier(pool) || claimString(c, "sub") != "node:"+node {
		return fail, invalidToken()
	}
	raw, ok := c["scope"].(string)
	if !ok {
		return fail, invalidToken()
	}
	scopes, e := normalizedScopes(strings.Split(raw, " "), false)
	if e != nil {
		return fail, invalidToken()
	}
	rm, ok := c["resources"].(map[string]any)
	if !ok {
		return fail, invalidToken()
	}
	resources, e := resourceLimits(rm)
	if e != nil {
		return fail, invalidToken()
	}
	if needsResources(scopes) {
		for _, k := range []string{"cpu_millicores", "memory_bytes", "disk_bytes"} {
			if _, ok := resources[k]; !ok {
				return fail, invalidToken()
			}
		}
	}
	subject := "node:" + node
	p := NodePrincipal{domain.PrincipalID(b.settings.Issuer, subject), subject, node, pool, claimString(c, "job_id"), claimString(c, "attempt_id"), claimString(c, "component_id"), claimString(c, "jti"), claimThumb(c), claimInt(c, "epoch"), claimInt(c, "iat"), claimInt(c, "exp"), scopes, resources}
	if validator == nil {
		validator = b.settings.NodeGrantValidator
	}
	if validator == nil {
		return fail, domain.Err(503, "node_grant_unavailable")
	}
	valid, e := validator(ctx, p)
	if e != nil {
		return fail, domain.Err(503, "node_grant_unavailable")
	}
	if !valid {
		return fail, invalidToken()
	}
	return p, nil
}
func (b *Broker) AuthenticateNodePlatform(ctx context.Context, authorization, peer string, validator RegistrationValidator) (PlatformNodePrincipal, error) {
	fail := PlatformNodePrincipal{}
	c, e := b.decode(authorization, b.settings.NodeAudience, peer, false)
	if e != nil {
		return fail, e
	}
	allowed := map[string]bool{"iss": true, "aud": true, "sub": true, "iat": true, "nbf": true, "exp": true, "jti": true, "cnf": true, "token_use": true, "scope": true, "node_id": true, "pool_id": true, "registration_id": true}
	if len(c) != len(allowed) {
		return fail, invalidToken()
	}
	for k := range c {
		if !allowed[k] {
			return fail, invalidToken()
		}
	}
	node, pool, reg := claimString(c, "node_id"), claimString(c, "pool_id"), claimString(c, "registration_id")
	if c["token_use"] != "node_platform" || c["scope"] != "qualify" || !validIdentifier(node) || !validIdentifier(pool) || !validIdentifier(reg) || c["sub"] != "node-platform:"+node || c["jti"] != reg {
		return fail, invalidToken()
	}
	sub := "node-platform:" + node
	p := PlatformNodePrincipal{domain.PrincipalID(b.settings.Issuer, sub), sub, node, pool, reg, claimThumb(c), []string{"qualify"}, claimInt(c, "exp")}
	if validator == nil {
		validator = b.settings.NodeRegistrationValidator
	}
	if validator == nil {
		return fail, domain.Err(503, "node_registration_unavailable")
	}
	valid, e := validator(ctx, p)
	if e != nil {
		return fail, domain.Err(503, "node_registration_unavailable")
	}
	if !valid {
		return fail, invalidToken()
	}
	return p, nil
}
func (b *Broker) AuthenticatePlatformNode(ctx context.Context, authorization, peer string, validator RegistrationValidator) (PlatformNodePrincipal, error) {
	return b.AuthenticateNodePlatform(ctx, authorization, peer, validator)
}

// PublicKeyPEM exposes only the verification key, never signing material.
func (b *Broker) PublicKeyPEM() []byte {
	p, e := x509.MarshalPKIXPublicKey(b.public)
	if e != nil {
		panic(fmt.Sprintf("unencodable RSA public key: %T", b.public))
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: p})
}
