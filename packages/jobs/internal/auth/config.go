// Package auth implements fixed-issuer human identity and durable browser sessions.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

const (
	SessionCookie   = "__Host-hf2l_jobs"
	LoginCookie     = "__Host-hf2l_jobs_login"
	SessionIdle     = 30 * time.Minute
	SessionAbsolute = 8 * time.Hour
	IdentityRecheck = 15 * time.Minute
	LoginLifetime   = 10 * time.Minute
)

type Config struct {
	OIDC                OIDCConfig
	SessionSecret       string
	PlatformOperatorIDs []string
}
type OIDCConfig struct {
	Issuer, ClientID, ClientSecret, RedirectURI, Audience string
	IntrospectionURL, JWKSURL, PublicKey                  string
	EndpointOrigins                                       []string
	TimeoutSeconds                                        float64
	JWKSCacheSeconds                                      int
	AllowLocalHTTP                                        bool
}

func (c OIDCConfig) defaults() OIDCConfig {
	if c.Audience == "" {
		c.Audience = "hf2l-jobs"
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 5
	}
	if c.JWKSCacheSeconds == 0 {
		c.JWKSCacheSeconds = 300
	}
	return c
}
func Origin(raw string) string {
	u, e := url.Parse(raw)
	if e != nil {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}
func requireTLS(raw string, local bool) error {
	u, e := url.Parse(raw)
	if e != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("URL requires a host without credentials or fragments")
	}
	if u.Scheme == "https" {
		return nil
	}
	ip := net.ParseIP(u.Hostname())
	if local && u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "testserver" || (ip != nil && ip.IsLoopback())) {
		return nil
	}
	return errors.New("HTTPS is required; development HTTP is limited to loopback")
}
func (c OIDCConfig) Validate() error {
	c = c.defaults()
	if c.Issuer == "" || c.ClientID == "" || c.RedirectURI == "" || c.Audience == "" {
		return errors.New("OIDC issuer, client ID, redirect URI and audience are required")
	}
	if e := requireTLS(c.Issuer, c.AllowLocalHTTP); e != nil {
		return e
	}
	issuer, _ := url.Parse(c.Issuer)
	if issuer.RawQuery != "" {
		return errors.New("OIDC issuer cannot contain a query")
	}
	if e := requireTLS(c.RedirectURI, c.AllowLocalHTTP); e != nil {
		return e
	}
	callback, _ := url.Parse(c.RedirectURI)
	if callback.RawQuery != "" || callback.Fragment != "" {
		return errors.New("OIDC redirect URI cannot contain query or fragment")
	}
	for _, o := range c.EndpointOrigins {
		if e := requireTLS(o, c.AllowLocalHTTP); e != nil {
			return e
		}
		u, _ := url.Parse(o)
		if Origin(o) != o || u.Path != "" || u.RawQuery != "" {
			return errors.New("OIDC endpoint origins must be exact HTTPS origins")
		}
	}
	for _, e := range []string{c.IntrospectionURL, c.JWKSURL} {
		if e != "" {
			if err := c.ValidateEndpoint(e); err != nil {
				return err
			}
		}
	}
	if c.PublicKey != "" && c.JWKSURL != "" {
		return errors.New("configure a public key or fixed JWKS URL, not both")
	}
	if math.IsNaN(c.TimeoutSeconds) || math.IsInf(c.TimeoutSeconds, 0) || c.TimeoutSeconds <= 0 || c.TimeoutSeconds > 30 || c.JWKSCacheSeconds < 1 || c.JWKSCacheSeconds > 300 {
		return errors.New("OIDC timeout/cache exceed configured bounds")
	}
	return nil
}
func (c OIDCConfig) ValidateEndpoint(endpoint string) error {
	if e := requireTLS(endpoint, c.AllowLocalHTTP); e != nil {
		return e
	}
	o := Origin(endpoint)
	if o == Origin(c.Issuer) {
		return nil
	}
	for _, v := range c.EndpointOrigins {
		if o == v {
			return nil
		}
	}
	return errors.New("OIDC endpoint origin is not explicitly trusted")
}

type Principal struct {
	ID               string `json:"principal_id"`
	Issuer           string `json:"issuer"`
	Subject          string `json:"subject"`
	PlatformOperator bool   `json:"platform_operator"`
}
type LoginStart struct {
	AuthorizationURL string
	StateCookie      string
}
type SessionIssue struct {
	SessionToken string
	CSRFToken    string
	Principal    Principal
}
type Identity struct{ Issuer, Subject, AccessToken, ProviderSID string }
type LogoutIdentity struct{ Subject, SID, JTI string }

func failure(status int, code string) error {
	e := domain.Err(status, code)
	e.Headers = map[string]string{}
	if status == 401 {
		e.Headers["WWW-Authenticate"] = "Bearer"
	}
	if status == 503 {
		e.Headers["Retry-After"] = "3"
	}
	return e
}
func errorStatus(err error) (int, string) {
	var d *domain.Error
	if errors.As(err, &d) {
		return d.Status, d.Code
	}
	return 500, "internal_error"
}
func equal(a, b string) bool { return hmac.Equal([]byte(a), []byte(b)) }
func digest(v string) string { d := sha256.Sum256([]byte(v)); return hex.EncodeToString(d[:]) }
func validateConfig(c Config) error {
	if e := c.OIDC.Validate(); e != nil {
		return e
	}
	if len([]byte(c.SessionSecret)) < 32 {
		return fmt.Errorf("session secret must contain at least32 bytes")
	}
	return nil
}

func (c Config) String() string       { return "authentication configuration (private)" }
func (c Config) GoString() string     { return c.String() }
func (c OIDCConfig) String() string   { return "OIDC configuration (private)" }
func (c OIDCConfig) GoString() string { return c.String() }
