package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SignupProvider is trusted operator configuration, never a caller-supplied
// issuer. BrokerAlias is an optional Keycloak identity-provider alias; the
// configured OIDC issuer remains the only authority for every returned identity.
type SignupProvider struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	BrokerAlias string `json:"broker_alias,omitempty"`
}

type SignupProviderInfo struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	SignupURL string `json:"signup_url"`
}

var signupIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
var brokerAliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func ValidateSignupProviders(providers []SignupProvider) error {
	if len(providers) > 16 {
		return errors.New("too many signup providers")
	}
	seen := map[string]bool{}
	for _, provider := range providers {
		if !signupIDPattern.MatchString(provider.ID) || seen[provider.ID] ||
			!utf8.ValidString(provider.Label) || utf8.RuneCountInString(provider.Label) < 1 ||
			utf8.RuneCountInString(provider.Label) > 100 || strings.TrimSpace(provider.Label) != provider.Label {
			return errors.New("invalid signup provider configuration")
		}
		for _, r := range provider.Label {
			if unicode.IsControl(r) {
				return errors.New("invalid signup provider label")
			}
		}
		if provider.BrokerAlias != "" && !brokerAliasPattern.MatchString(provider.BrokerAlias) {
			return errors.New("invalid signup broker alias")
		}
		seen[provider.ID] = true
	}
	return nil
}

// ParseSignupProviders rejects unknown fields and trailing documents. Empty
// configuration uses the ordinary organization login, not an external issuer.
func ParseSignupProviders(raw string) ([]SignupProvider, error) {
	if len(raw) > 16384 || !utf8.ValidString(raw) {
		return nil, errors.New("invalid signup provider configuration")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var providers []SignupProvider
	if err := decoder.Decode(&providers); err != nil || providers == nil {
		return nil, errors.New("signup providers must be an array")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("invalid signup provider configuration")
	}
	if err := ValidateSignupProviders(providers); err != nil {
		return nil, err
	}
	return providers, nil
}

func (s *Service) configuredSignupProviders() []SignupProvider {
	if len(s.Config.SignupProviders) == 0 {
		return []SignupProvider{{ID: "organization", Label: "Organization account"}}
	}
	return s.Config.SignupProviders
}

// SignupProviders exposes display choices and local URLs only. Private client
// secrets, upstream identities, and arbitrary redirect addresses are absent.
func (s *Service) SignupProviders() []SignupProviderInfo {
	providers := s.configuredSignupProviders()
	result := make([]SignupProviderInfo, 0, len(providers))
	for _, provider := range providers {
		result = append(result, SignupProviderInfo{ID: provider.ID, Label: provider.Label,
			SignupURL: "/auth/signup?provider=" + url.QueryEscape(provider.ID)})
	}
	return result
}

func (s *Service) BeginSignup(ctx context.Context, providerID string) (LoginStart, error) {
	if !signupIDPattern.MatchString(providerID) {
		return LoginStart{}, failure(422, "invalid_signup_provider")
	}
	for _, provider := range s.configuredSignupProviders() {
		if provider.ID == providerID {
			return s.beginLogin(ctx, provider.BrokerAlias)
		}
	}
	return LoginStart{}, failure(404, "signup_provider_not_found")
}

type brokerAuthorizationProvider interface {
	AuthorizationURLForBroker(context.Context, string, string, string, string) (string, error)
}

// AuthorizationURLForBroker adds only an operator-selected broker hint to the
// existing fixed-issuer, PKCE-protected authorization request. It cannot alter
// callback, scopes, token verification, or account identity derivation.
func (p *OIDCProvider) AuthorizationURLForBroker(ctx context.Context, state, nonce, challenge, alias string) (string, error) {
	if !brokerAliasPattern.MatchString(alias) {
		return "", failure(422, "invalid_signup_provider")
	}
	target, err := p.AuthorizationURL(ctx, state, nonce, challenge)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(target)
	if err != nil {
		return "", failure(503, "identity_provider_invalid_response")
	}
	query := u.Query()
	query.Set("kc_idp_hint", alias)
	u.RawQuery = query.Encode()
	return u.String(), nil
}
