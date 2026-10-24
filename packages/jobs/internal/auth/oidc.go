package auth

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
)

const LogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

type OIDCProvider struct {
	Config                 OIDCConfig
	Client                 *http.Client
	Clock                  func() time.Time
	publicKey              *rsa.PublicKey
	discoveryMu            sync.Mutex
	discovery              map[string]any
	keyMu                  sync.Mutex
	keys                   map[string]*rsa.PublicKey
	keysUntil, lastRefresh time.Time
}

func NewOIDCProvider(config OIDCConfig, client *http.Client) (*OIDCProvider, error) {
	config = config.defaults()
	if e := config.Validate(); e != nil {
		return nil, e
	}
	if client == nil {
		client = &http.Client{}
	}
	copyClient := *client
	copyClient.Timeout = time.Duration(config.TimeoutSeconds * float64(time.Second))
	copyClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	p := &OIDCProvider{Config: config, Client: &copyClient, Clock: time.Now, keys: map[string]*rsa.PublicKey{}}
	if config.PublicKey != "" {
		block, rest := pem.Decode([]byte(config.PublicKey))
		if block == nil || len(bytes.TrimSpace(rest)) != 0 {
			return nil, errors.New("OIDC verification requires an RSA public key")
		}
		key, e := x509.ParsePKIXPublicKey(block.Bytes)
		if e != nil {
			if k, e2 := x509.ParsePKCS1PublicKey(block.Bytes); e2 == nil {
				key = k
				e = nil
			}
		}
		if e != nil {
			return nil, errors.New("OIDC verification requires an RSA public key")
		}
		k, ok := key.(*rsa.PublicKey)
		if !ok || k.N.BitLen() < 2048 {
			return nil, errors.New("OIDC verification requires an RSA key of at least2048 bits")
		}
		p.publicKey = k
	}
	return p, nil
}
func (p *OIDCProvider) request(ctx context.Context, method, target string, form url.Values) (map[string]any, error) {
	if e := p.Config.ValidateEndpoint(target); e != nil {
		return nil, failure(503, "identity_provider_unavailable")
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, e := http.NewRequestWithContext(ctx, method, target, body)
	if e != nil {
		return nil, failure(503, "identity_provider_unavailable")
	}
	req.Header.Set("Accept", "application/json")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if p.Config.ClientSecret != "" {
			req.SetBasicAuth(p.Config.ClientID, p.Config.ClientSecret)
		}
	}
	response, e := p.Client.Do(req)
	if e != nil {
		return nil, failure(503, "identity_provider_unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, failure(503, "identity_provider_unavailable")
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 1_048_577))
	if e != nil {
		return nil, failure(503, "identity_provider_unavailable")
	}
	if len(raw) > 1_048_576 {
		return nil, failure(503, "identity_provider_invalid_response")
	}
	var data map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if e = decoder.Decode(&data); e != nil || data == nil {
		return nil, failure(503, "identity_provider_invalid_response")
	}
	var extra any
	if e = decoder.Decode(&extra); e != io.EOF {
		return nil, failure(503, "identity_provider_invalid_response")
	}
	return data, nil
}
func stringValue(m map[string]any, key string) string { v, _ := m[key].(string); return v }
func contains(values any, expected string) bool {
	switch a := values.(type) {
	case []any:
		for _, v := range a {
			if v == expected {
				return true
			}
		}
	case []string:
		for _, v := range a {
			if v == expected {
				return true
			}
		}
	}
	return false
}
func (p *OIDCProvider) Discovery(ctx context.Context) (map[string]any, error) {
	p.discoveryMu.Lock()
	defer p.discoveryMu.Unlock()
	if p.discovery != nil {
		return p.discovery, nil
	}
	data, e := p.request(ctx, http.MethodGet, strings.TrimRight(p.Config.Issuer, "/")+"/.well-known/openid-configuration", nil)
	if e != nil {
		return nil, e
	}
	if stringValue(data, "issuer") != p.Config.Issuer {
		return nil, failure(503, "identity_provider_issuer_mismatch")
	}
	for _, name := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri"} {
		endpoint, ok := data[name].(string)
		if !ok {
			return nil, failure(503, "identity_provider_invalid_response")
		}
		if e := p.Config.ValidateEndpoint(endpoint); e != nil {
			return nil, failure(503, "identity_provider_endpoint_rejected")
		}
	}
	if !contains(data["code_challenge_methods_supported"], "S256") {
		return nil, failure(503, "identity_provider_pkce_required")
	}
	if !contains(data["id_token_signing_alg_values_supported"], "RS256") {
		return nil, failure(503, "identity_provider_algorithm_rejected")
	}
	if v, exists := data["introspection_endpoint"]; exists && v != nil && v != "" {
		endpoint, ok := v.(string)
		if !ok {
			return nil, failure(503, "identity_provider_endpoint_rejected")
		}
		if e := p.Config.ValidateEndpoint(endpoint); e != nil {
			return nil, failure(503, "identity_provider_endpoint_rejected")
		}
	}
	p.discovery = data
	return data, nil
}
func (p *OIDCProvider) AuthorizationURL(ctx context.Context, state, nonce, challenge string) (string, error) {
	data, e := p.Discovery(ctx)
	if e != nil {
		return "", e
	}
	u, e := url.Parse(stringValue(data, "authorization_endpoint"))
	if e != nil {
		return "", failure(503, "identity_provider_invalid_response")
	}
	q := u.Query()
	for k, v := range map[string]string{"response_type": "code", "response_mode": "query", "client_id": p.Config.ClientID, "redirect_uri": p.Config.RedirectURI, "scope": "openid", "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256", "prompt": "login"} {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
func (p *OIDCProvider) signingKey(ctx context.Context, token *jwt.Token) (any, error) {
	if token.Method != jwt.SigningMethodRS256 {
		return nil, failure(401, "invalid_access_token")
	}
	for _, name := range []string{"jku", "x5u", "jwk"} {
		if _, ok := token.Header[name]; ok {
			return nil, failure(401, "invalid_access_token")
		}
	}
	if p.publicKey != nil {
		return p.publicKey, nil
	}
	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" || utf8.RuneCountInString(kid) > 256 {
		return nil, failure(401, "invalid_access_token")
	}
	p.keyMu.Lock()
	defer p.keyMu.Unlock()
	now := p.Clock()
	if now.Before(p.keysUntil) {
		if key := p.keys[kid]; key != nil {
			return key, nil
		}
	}
	if now.Before(p.keysUntil) && now.Sub(p.lastRefresh) < 2*time.Second {
		return nil, failure(401, "invalid_access_token")
	}
	endpoint := p.Config.JWKSURL
	if endpoint == "" {
		d, e := p.Discovery(ctx)
		if e != nil {
			return nil, e
		}
		endpoint = stringValue(d, "jwks_uri")
	}
	data, e := p.request(ctx, http.MethodGet, endpoint, nil)
	if e != nil {
		return nil, e
	}
	keys, ok := data["keys"].([]any)
	if !ok || len(keys) > 100 {
		return nil, failure(503, "identity_provider_invalid_jwks")
	}
	parsed := map[string]*rsa.PublicKey{}
	for _, raw := range keys {
		value, ok := raw.(map[string]any)
		if !ok || stringValue(value, "kty") != "RSA" {
			continue
		}
		if v, exists := value["use"]; exists && v != "sig" {
			continue
		}
		if v, exists := value["alg"]; exists && v != "RS256" {
			continue
		}
		if _, exists := value["d"]; exists {
			return nil, failure(503, "identity_provider_invalid_jwks")
		}
		id := stringValue(value, "kid")
		if id == "" || parsed[id] != nil {
			return nil, failure(503, "identity_provider_invalid_jwks")
		}
		nraw, e := base64.RawURLEncoding.DecodeString(stringValue(value, "n"))
		if e != nil || len(nraw) == 0 {
			return nil, failure(503, "identity_provider_invalid_jwks")
		}
		eraw, e := base64.RawURLEncoding.DecodeString(stringValue(value, "e"))
		if e != nil || len(eraw) == 0 || len(eraw) > 4 {
			return nil, failure(503, "identity_provider_invalid_jwks")
		}
		exponent := new(big.Int).SetBytes(eraw).Int64()
		n := new(big.Int).SetBytes(nraw)
		if exponent < 3 || exponent > math.MaxInt32 || exponent%2 == 0 || n.BitLen() < 2048 {
			return nil, failure(503, "identity_provider_invalid_jwks")
		}
		parsed[id] = &rsa.PublicKey{N: n, E: int(exponent)}
	}
	p.keys = parsed
	p.lastRefresh = now
	p.keysUntil = now.Add(time.Duration(p.Config.JWKSCacheSeconds) * time.Second)
	if key := parsed[kid]; key != nil {
		return key, nil
	}
	return nil, failure(401, "invalid_access_token")
}
func numeric(v any) (float64, bool) {
	var f float64
	switch n := v.(type) {
	case json.Number:
		var e error
		f, e = n.Float64()
		if e != nil {
			return 0, false
		}
	case float64:
		f = n
	case float32:
		f = float64(n)
	case int:
		f = float64(n)
	case int64:
		f = float64(n)
	default:
		return 0, false
	}
	return f, !math.IsNaN(f) && !math.IsInf(f, 0)
}
func (p *OIDCProvider) decode(ctx context.Context, raw, audience string, requireSubject bool) (jwt.MapClaims, error) {
	if raw == "" || len(raw) > 65_536 {
		return nil, failure(401, "invalid_access_token")
	}
	claims := jwt.MapClaims{}
	token, e := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) { return p.signingKey(ctx, t) }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(p.Config.Issuer), jwt.WithAudience(audience), jwt.WithIssuedAt(), jwt.WithExpirationRequired(), jwt.WithJSONNumber(), jwt.WithTimeFunc(p.Clock))
	if e != nil {
		// Provider/network failures remain retryable instead of being mislabeled invalid credentials.
		if status, code := errorStatus(e); status == 503 {
			return nil, failure(status, code)
		}
		return nil, failure(401, "invalid_access_token")
	}
	if token == nil || !token.Valid {
		return nil, failure(401, "invalid_access_token")
	}
	iat, ok1 := numeric(claims["iat"])
	exp, ok2 := numeric(claims["exp"])
	if !ok1 || !ok2 || exp <= iat {
		return nil, failure(401, "invalid_access_token")
	}
	if requireSubject {
		s, ok := claims["sub"].(string)
		if !ok || s == "" || utf8.RuneCountInString(s) > 256 {
			return nil, failure(401, "invalid_access_token")
		}
	}
	return claims, nil
}
func halfHash(v string) (string, error) {
	for _, r := range v {
		if r > 127 {
			return "", errors.New("hash input must be ASCII")
		}
	}
	h := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(h[:len(h)/2]), nil
}
func (p *OIDCProvider) ExchangeCode(ctx context.Context, code, verifier, nonce string) (Identity, error) {
	if len(code) < 1 || len(code) > 8192 {
		return Identity{}, failure(401, "invalid_authorization_response")
	}
	d, e := p.Discovery(ctx)
	if e != nil {
		return Identity{}, e
	}
	result, e := p.request(ctx, http.MethodPost, stringValue(d, "token_endpoint"), url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {p.Config.RedirectURI}, "client_id": {p.Config.ClientID}})
	if e != nil {
		return Identity{}, e
	}
	raw, _ := result["id_token"].(string)
	access := ""
	if v, exists := result["access_token"]; exists {
		var ok bool
		access, ok = v.(string)
		if !ok || len(access) > 65_536 {
			return Identity{}, failure(401, "invalid_authorization_response")
		}
	}
	claims, e := p.decode(ctx, raw, p.Config.ClientID, true)
	if e != nil {
		return Identity{}, e
	}
	gotNonce, ok := claims["nonce"].(string)
	if !ok || !isASCII(gotNonce) || !equal(gotNonce, nonce) {
		return Identity{}, failure(401, "invalid_oidc_nonce")
	}
	audiences, e := claims.GetAudience()
	if e != nil {
		return Identity{}, failure(401, "invalid_oidc_authorized_party")
	}
	if _, exists := claims["azp"]; len(audiences) > 1 || exists {
		if claims["azp"] != p.Config.ClientID {
			return Identity{}, failure(401, "invalid_oidc_authorized_party")
		}
	}
	for name, value := range map[string]string{"at_hash": access, "c_hash": code} {
		if expected, exists := claims[name]; exists {
			want, ok := expected.(string)
			actual, e := halfHash(value)
			if !ok || value == "" || e != nil || !equal(want, actual) {
				return Identity{}, failure(401, "invalid_oidc_token_hash")
			}
		}
	}
	sid := ""
	if v, exists := claims["sid"]; exists && v != nil {
		var ok bool
		sid, ok = v.(string)
		if !ok || sid == "" || utf8.RuneCountInString(sid) > 256 {
			return Identity{}, failure(401, "invalid_oidc_session")
		}
	}
	return Identity{Issuer: p.Config.Issuer, Subject: claims["sub"].(string), AccessToken: access, ProviderSID: sid}, nil
}
func isASCII(v string) bool {
	for _, r := range v {
		if r > 127 {
			return false
		}
	}
	return true
}
func (p *OIDCProvider) introspectionEndpoint(ctx context.Context) (string, error) {
	if p.Config.IntrospectionURL != "" {
		return p.Config.IntrospectionURL, nil
	}
	d, e := p.Discovery(ctx)
	if e != nil {
		return "", e
	}
	return stringValue(d, "introspection_endpoint"), nil
}
func (p *OIDCProvider) OnlineCheck(ctx context.Context, access, subject string) (bool, error) {
	endpoint, e := p.introspectionEndpoint(ctx)
	if e != nil {
		return false, e
	}
	if endpoint == "" || access == "" {
		return false, failure(401, "fresh_authorization_required")
	}
	result, e := p.request(ctx, http.MethodPost, endpoint, url.Values{"token": {access}, "client_id": {p.Config.ClientID}})
	if e != nil {
		return false, e
	}
	if result["active"] != true || result["sub"] != subject {
		return false, nil
	}
	if v, exists := result["iss"]; exists && v != p.Config.Issuer {
		return false, nil
	}
	bound := result["client_id"] == p.Config.ClientID
	switch a := result["aud"].(type) {
	case string:
		bound = bound || a == p.Config.ClientID || a == p.Config.Audience
	case []any:
		for _, v := range a {
			bound = bound || v == p.Config.ClientID || v == p.Config.Audience
		}
	}
	if !bound {
		return false, nil
	}
	if v, exists := result["exp"]; exists {
		n, ok := numeric(v)
		if !ok || n <= float64(p.Clock().UnixNano())/1e9 {
			return false, nil
		}
	}
	return true, nil
}
func (p *OIDCProvider) AuthenticateAccessToken(ctx context.Context, raw string) (Identity, error) {
	if raw == "" || len(raw) > 65_536 {
		return Identity{}, failure(401, "invalid_access_token")
	}
	// ParseUnverified only checks the header before verified decoding; it never establishes identity.
	unverified, _, e := jwt.NewParser(jwt.WithJSONNumber()).ParseUnverified(raw, jwt.MapClaims{})
	if e != nil || unverified.Header["typ"] != "at+jwt" {
		return Identity{}, failure(401, "invalid_access_token")
	}
	claims, e := p.decode(ctx, raw, p.Config.Audience, true)
	if e != nil {
		return Identity{}, e
	}
	scope, ok := claims["scope"].(string)
	if !ok {
		return Identity{}, failure(401, "invalid_access_scope")
	}
	found := false
	for _, v := range strings.Fields(scope) {
		if v == "jobs" {
			found = true
		}
	}
	if !found {
		return Identity{}, failure(401, "invalid_access_scope")
	}
	endpoint, e := p.introspectionEndpoint(ctx)
	if e != nil {
		return Identity{}, e
	}
	if endpoint != "" {
		active, e := p.OnlineCheck(ctx, raw, claims["sub"].(string))
		if e != nil {
			return Identity{}, e
		}
		if !active {
			return Identity{}, failure(401, "identity_revoked")
		}
	} else {
		iat, _ := numeric(claims["iat"])
		if float64(p.Clock().UnixNano())/1e9-iat >= 900 {
			return Identity{}, failure(401, "fresh_authorization_required")
		}
	}
	return Identity{Issuer: p.Config.Issuer, Subject: claims["sub"].(string)}, nil
}
func (p *OIDCProvider) LogoutIdentity(ctx context.Context, raw string) (LogoutIdentity, error) {
	// Logout tokens have no required subject or exp. Verify signature and issuer/client audience separately.
	if raw == "" || len(raw) > 65_536 {
		return LogoutIdentity{}, failure(401, "invalid_logout_token")
	}
	claims := jwt.MapClaims{}
	token, e := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) { return p.signingKey(ctx, t) }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(p.Config.Issuer), jwt.WithAudience(p.Config.ClientID), jwt.WithIssuedAt(), jwt.WithJSONNumber(), jwt.WithTimeFunc(p.Clock))
	if e != nil {
		if status, code := errorStatus(e); status == 503 {
			return LogoutIdentity{}, failure(status, code)
		}
		return LogoutIdentity{}, failure(401, "invalid_logout_token")
	}
	if token == nil || !token.Valid {
		return LogoutIdentity{}, failure(401, "invalid_logout_token")
	}
	iat, ok := numeric(claims["iat"])
	if !ok || float64(p.Clock().UnixNano())/1e9-iat > 300 {
		return LogoutIdentity{}, failure(401, "invalid_logout_token")
	}
	if _, exists := claims["nonce"]; exists {
		return LogoutIdentity{}, failure(401, "invalid_logout_token")
	}
	events, ok := claims["events"].(map[string]any)
	if !ok || len(events) != 1 {
		return LogoutIdentity{}, failure(401, "invalid_logout_token")
	}
	event, ok := events[LogoutEvent].(map[string]any)
	if !ok || len(event) != 0 {
		return LogoutIdentity{}, failure(401, "invalid_logout_token")
	}
	out := LogoutIdentity{}
	for name, target := range map[string]*string{"sub": &out.Subject, "sid": &out.SID, "jti": &out.JTI} {
		if v, exists := claims[name]; exists && v != nil {
			s, ok := v.(string)
			if !ok || s == "" || utf8.RuneCountInString(s) > 256 {
				return LogoutIdentity{}, failure(401, "invalid_logout_token")
			}
			*target = s
		}
	}
	if out.JTI == "" || (out.Subject == "" && out.SID == "") {
		return LogoutIdentity{}, failure(401, "invalid_logout_token")
	}
	return out, nil
}
