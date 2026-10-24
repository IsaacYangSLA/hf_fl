// Package auth validates fixed-issuer Exchange identities without database access.
package auth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/golang-jwt/jwt/v5"
)

const maxTokenBytes = 65536

var thumbprintPattern = regexp.MustCompile("^[A-Za-z0-9_-]{43}$")

// Options are trusted construction hooks. Production clients verify HTTPS using
// the configured platform roots; tests can supply their own explicitly trusted CA.
type Options struct {
	HTTPClient *http.Client
	Now        func() time.Time
}

type Authenticator struct {
	settings      config.AuthSettings
	now           func() time.Time
	client        *http.Client
	publicKey     *rsa.PublicKey
	workloadKey   *rsa.PublicKey
	keyLock       chan struct{}
	cache         map[string]*rsa.PublicKey
	cacheUntil    time.Time
	retryAfter    time.Time
	keyTimeout    time.Duration
	cacheLifetime time.Duration
}

func New(settings config.AuthSettings) (*Authenticator, error) {
	return NewWithOptions(settings, Options{})
}

func NewWithOptions(settings config.AuthSettings, options Options) (*Authenticator, error) {
	if err := settings.Validate(); err != nil {
		return nil, errors.New("invalid authentication configuration")
	}
	if math.IsNaN(settings.JWKSTimeout) || math.IsInf(settings.JWKSTimeout, 0) ||
		settings.JWKSTimeout <= 0 || settings.JWKSTimeout >= float64(math.MaxInt64)/float64(time.Second) ||
		settings.JWKSCacheSeconds <= 0 || settings.JWKSCacheSeconds > math.MaxInt64/int64(time.Second) {
		return nil, errors.New("invalid authentication configuration")
	}
	a := &Authenticator{
		settings: settings, now: options.Now, keyLock: make(chan struct{}, 1),
		keyTimeout:    time.Duration(settings.JWKSTimeout * float64(time.Second)),
		cacheLifetime: time.Duration(settings.JWKSCacheSeconds) * time.Second,
		cache:         map[string]*rsa.PublicKey{},
	}
	if a.now == nil {
		a.now = time.Now
	}
	base := options.HTTPClient
	if base == nil {
		base = http.DefaultClient
	}
	copied := *base
	if copied.Timeout <= 0 || copied.Timeout > a.keyTimeout {
		copied.Timeout = a.keyTimeout
	}
	// Keys are retrieved only from the configured fixed endpoint. Redirects may
	// not silently substitute another authority or downgrade HTTPS.
	copied.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	a.client = &copied
	var err error
	if settings.JWKSURL == "" {
		a.publicKey, err = parsePublicKey(settings.PublicKey)
		if err != nil {
			return nil, errors.New("invalid authentication public key")
		}
	}
	if settings.WorkloadsEnabled() {
		a.workloadKey, err = parsePublicKey(settings.WorkloadPublicKey)
		if err != nil {
			return nil, errors.New("invalid workload public key")
		}
	}
	return a, nil
}

func (a *Authenticator) WorkloadAudience() string {
	return a.settings.WorkloadAudience
}

func invalidToken() error {
	return &domain.Error{Status: 401, Code: "invalid_access_token", Detail: "invalid_access_token",
		Headers: map[string]string{"WWW-Authenticate": "Bearer"}}
}

func identityUnavailable() error {
	return &domain.Error{Status: 503, Code: "identity_provider_unavailable", Detail: "identity_provider_unavailable",
		Headers: map[string]string{"Retry-After": "3"}}
}

func parsePublicKey(value string) (*rsa.PublicKey, error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("invalid public key")
	}
	var key *rsa.PublicKey
	switch block.Type {
	case "PUBLIC KEY":
		value, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, errors.New("invalid public key")
		}
		var ok bool
		key, ok = value.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("invalid public key")
		}
	case "RSA PUBLIC KEY":
		var err error
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, errors.New("invalid public key")
		}
	case "CERTIFICATE":
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("invalid public key")
		}
		var ok bool
		key, ok = certificate.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("invalid public key")
		}
	default:
		return nil, errors.New("invalid public key")
	}
	if key.N == nil || key.N.Sign() <= 0 || key.N.BitLen() < 1024 || key.N.BitLen() > 16384 || key.E < 3 || key.E%2 == 0 {
		return nil, errors.New("invalid public key")
	}
	return key, nil
}

func tokenParts(authorization string) (string, domain.Object, domain.Object, error) {
	scheme, token, ok := strings.Cut(authorization, " ")
	if !ok || !strings.EqualFold(scheme, "bearer") || token == "" || len(token) > maxTokenBytes {
		return "", nil, nil, invalidToken()
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", nil, nil, invalidToken()
	}
	decode := func(value string) (domain.Object, bool) {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
		if err != nil {
			return nil, false
		}
		decoded, err := domain.DecodeJSON(raw)
		if err != nil {
			return nil, false
		}
		result, ok := decoded.(map[string]any)
		return result, ok
	}
	header, ok := decode(parts[0])
	if !ok || header["typ"] != "at+jwt" || header["alg"] != "RS256" {
		return "", nil, nil, invalidToken()
	}
	claims, ok := decode(parts[1])
	if !ok {
		return "", nil, nil, invalidToken()
	}
	return token, header, claims, nil
}

func validString(value any, limit int) (string, bool) {
	result, ok := value.(string)
	return result, ok && utf8.ValidString(result) && result != "" && utf8.RuneCountInString(result) <= limit
}

func numeric(value any) (float64, bool) {
	switch n := value.(type) {
	case json.Number:
		value, err := n.Float64()
		return value, err == nil && !math.IsNaN(value) && !math.IsInf(value, 0)
	case float64:
		return n, !math.IsNaN(n) && !math.IsInf(n, 0)
	case float32:
		value := float64(n)
		return value, !math.IsNaN(value) && !math.IsInf(value, 0)
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}

func validAudience(value any, required string, strict bool) bool {
	if single, ok := value.(string); ok {
		return single == required
	}
	if strict {
		return false
	}
	values, ok := value.([]any)
	if !ok || len(values) == 0 {
		return false
	}
	matched := false
	for _, value := range values {
		s, ok := value.(string)
		if !ok {
			return false
		}
		if s == required {
			matched = true
		}
	}
	return matched
}

func hasScope(value any, required string) bool {
	scope, ok := value.(string)
	if !ok {
		return false
	}
	for _, part := range strings.Fields(scope) {
		if part == required {
			return true
		}
	}
	return false
}

func legacyNumericDate(value any) (float64, bool) {
	if number, ok := numeric(value); ok {
		return number, true
	}
	switch input := value.(type) {
	case bool:
		if input {
			return 1, true
		}
		return 0, true
	case string:
		// PyJWT's historical human-token validation calls int(). Preserve
		// decimal integer strings without accepting float/exponent strings.
		value := strings.TrimSpace(input)
		if len(value) == 0 || len(value) > 4300 {
			return 0, false
		}
		digits := value
		if digits[0] == '+' || digits[0] == '-' {
			digits = digits[1:]
		}
		if digits == "" {
			return 0, false
		}
		for i, digit := range []byte(digits) {
			if digit >= '0' && digit <= '9' {
				continue
			}
			if digit != '_' || i == 0 || i+1 == len(digits) || digits[i-1] < '0' || digits[i-1] > '9' || digits[i+1] < '0' || digits[i+1] > '9' {
				return 0, false
			}
		}
		integer, ok := new(big.Int).SetString(strings.ReplaceAll(value, "_", ""), 10)
		if !ok {
			return 0, false
		}
		result, _ := new(big.Float).SetInt(integer).Float64()
		if math.IsInf(result, 0) {
			// Human dates are only compared to now; saturation preserves the
			// comparison for arbitrarily large historical integer strings.
			return math.Copysign(math.MaxFloat64, result), true
		}
		return result, true
	default:
		return 0, false
	}
}

func validateTimes(claims domain.Object, now time.Time, legacy bool) (float64, float64, bool) {
	parse := numeric
	if legacy {
		parse = legacyNumericDate
	}
	expiry, expOK := parse(claims["exp"])
	issued, iatOK := parse(claims["iat"])
	seconds := float64(now.UnixMicro()) / 1e6
	// PyJWT validates NumericDate through int(), while workload lifetime and
	// identity retain the original numeric values.
	if !expOK || !iatOK || math.Trunc(expiry) <= seconds || math.Trunc(issued) > seconds {
		return 0, 0, false
	}
	if value, exists := claims["nbf"]; exists {
		start, ok := parse(value)
		if !ok || math.Trunc(start) > seconds {
			return 0, 0, false
		}
	}
	return expiry, issued, true
}

// Authenticate verifies a human or certificate-bound workload identity. Current
// memberships and workload grants must still be checked transactionally by service.
func (a *Authenticator) Authenticate(ctx context.Context, authorization string, managed bool, certificateThumbprint string) (domain.Principal, error) {
	return a.authenticate(ctx, authorization, managed, certificateThumbprint)
}

// AuthenticateTransfer applies the private gateway's strict single audience and
// transfer scope, in addition to ordinary workload signature/certificate checks.
func (a *Authenticator) AuthenticateTransfer(ctx context.Context, authorization, certificateThumbprint string) (domain.Principal, error) {
	principal, err := a.authenticate(ctx, authorization, true, certificateThumbprint)
	if err != nil {
		return domain.Principal{}, err
	}
	if principal.Workload == nil {
		return domain.Principal{}, domain.Err(401, "workload_identity_required")
	}
	_, _, claims, err := tokenParts(authorization)
	if err != nil || !validAudience(claims["aud"], a.settings.WorkloadAudience, true) || !hasScope(claims["scope"], "transfer") {
		return domain.Principal{}, domain.Err(401, "invalid_workload_token")
	}
	return principal, nil
}

func (a *Authenticator) authenticate(ctx context.Context, authorization string, managed bool, certificateThumbprint string) (domain.Principal, error) {
	empty := domain.Principal{}
	token, header, claims, err := tokenParts(authorization)
	if err != nil {
		return empty, err
	}
	issuer, ok := claims["iss"].(string)
	if !ok {
		return empty, invalidToken()
	}
	workload := a.settings.WorkloadsEnabled() && issuer == a.settings.WorkloadIssuer
	key := a.publicKey
	audience := a.settings.Audience
	if workload {
		if !managed || !thumbprintPattern.MatchString(certificateThumbprint) {
			return empty, invalidToken()
		}
		key, audience = a.workloadKey, a.settings.WorkloadAudience
	} else {
		if issuer != a.settings.Issuer {
			return empty, invalidToken()
		}
		if a.settings.JWKSURL != "" {
			key, err = a.signingKey(ctx, header)
			if err != nil {
				return empty, err
			}
		}
	}
	parsed, err := jwt.Parse(token, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, errors.New("invalid signing method")
		}
		return key, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithJSONNumber(), jwt.WithoutClaimsValidation(), jwt.WithStrictDecoding())
	if err != nil || parsed == nil || !parsed.Valid || !validAudience(claims["aud"], audience, false) {
		return empty, invalidToken()
	}
	expiry, issued, ok := validateTimes(claims, a.now(), !workload)
	if !ok {
		return empty, invalidToken()
	}
	subject, ok := validString(claims["sub"], 256)
	if !ok {
		return empty, invalidToken()
	}
	if !workload {
		if !hasScope(claims["scope"], "exchange") {
			return empty, invalidToken()
		}
		return domain.Principal{ID: domain.PrincipalID(a.settings.Issuer, subject), Subject: subject,
			BootstrapAdmin: a.settings.AdminSubject != "" && subject == a.settings.AdminSubject}, nil
	}
	for field, limit := range map[string]int{"jti": 64, "space_id": 64, "job_id": 128, "attempt_id": 128, "component_id": 128} {
		if _, ok := validString(claims[field], limit); !ok {
			return empty, invalidToken()
		}
	}
	epoch, ok := domain.Int64(claims["epoch"])
	if !ok || epoch < 1 || expiry-issued <= 0 || expiry-issued > 300 {
		return empty, invalidToken()
	}
	cnf, ok := claims["cnf"].(map[string]any)
	if !ok || len(cnf) != 1 {
		return empty, invalidToken()
	}
	binding, ok := cnf["x5t#S256"].(string)
	if !ok || !constantEqual(binding, certificateThumbprint) {
		return empty, invalidToken()
	}
	grantID := claims["jti"].(string)
	if value, exists := claims["grant_id"]; exists && value != grantID {
		return empty, invalidToken()
	}
	identity := &domain.WorkloadIdentity{
		GrantID: grantID, SpaceID: claims["space_id"].(string), JobID: claims["job_id"].(string),
		AttemptID: claims["attempt_id"].(string), ComponentID: claims["component_id"].(string),
		Epoch: epoch, CertificateThumbprint: certificateThumbprint, ExpiresAt: expiry,
	}
	return domain.Principal{ID: domain.PrincipalID(a.settings.WorkloadIssuer, subject), Subject: subject, Workload: identity}, nil
}
