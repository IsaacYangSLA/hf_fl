package auth

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

func TestSignupUsesTrustedBrokerAndExistingPKCEState(t *testing.T) {
	s, f := testService(t)
	s.Config.SignupProviders = []SignupProvider{{ID: "github", Label: "GitHub", BrokerAlias: "github-approved"}}
	start, err := s.BeginSignup(context.Background(), "github")
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(start.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	query := target.Query()
	if target.Scheme+"://"+target.Host != testIssuer || query.Get("kc_idp_hint") != "github-approved" ||
		query.Get("redirect_uri") != s.Config.OIDC.RedirectURI || query.Get("code_challenge_method") != "S256" ||
		query.Get("scope") != "openid" || query.Get("nonce") == "" || query.Get("state") == "" {
		t.Fatalf("signup changed trust or login contract: %s", start.AuthorizationURL)
	}
	f.nonce, f.challenge = query.Get("nonce"), query.Get("code_challenge")
	_, err = s.FinishLogin(context.Background(), "test-code", query.Get("state"), strings.Repeat("x", 43))
	expectError(t, err, 401, "invalid_authorization_state")
	issue, err := s.FinishLogin(context.Background(), "test-code", query.Get("state"), start.StateCookie)
	if err != nil {
		t.Fatal(err)
	}
	if issue.Principal.ID != domain.PrincipalID(testIssuer, "alice") {
		t.Fatal("signup changed principal identity")
	}
	_, err = s.FinishLogin(context.Background(), "test-code", query.Get("state"), start.StateCookie)
	expectError(t, err, 401, "invalid_authorization_state")
}

func TestSignupUnknownProvidersFailBeforeCreatingLoginState(t *testing.T) {
	s, _ := testService(t)
	for _, id := range []string{"https://attacker.invalid", "organization?issuer=bad", "", "GITHUB", "a/b"} {
		_, err := s.BeginSignup(context.Background(), id)
		expectError(t, err, 422, "invalid_signup_provider")
	}
	_, err := s.BeginSignup(context.Background(), "unlisted")
	expectError(t, err, 404, "signup_provider_not_found")
	rows, err := s.DB.All(context.Background(), "SELECT * FROM auth_login_attempts")
	if err != nil || len(rows) != 0 {
		t.Fatalf("unlisted signup created login state: %v %v", rows, err)
	}
}

func TestSignupChoicesExposeOnlySafeLocalURLs(t *testing.T) {
	s, _ := testService(t)
	providers := s.SignupProviders()
	if len(providers) != 1 || providers[0].ID != "organization" || providers[0].SignupURL != "/auth/signup?provider=organization" {
		t.Fatalf("default: %#v", providers)
	}
	s.Config.SignupProviders = []SignupProvider{{ID: "github", Label: "GitHub", BrokerAlias: "private-broker-alias"}}
	encoded, _ := json.Marshal(s.SignupProviders())
	if strings.Contains(string(encoded), "broker") || strings.Contains(string(encoded), "client_secret") || strings.Contains(string(encoded), testIssuer) {
		t.Fatal("public signup choices exposed private configuration")
	}
	start, err := s.BeginLogin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse(start.AuthorizationURL)
	if target.Query().Has("kc_idp_hint") {
		t.Fatal("ordinary login inherited signup choice")
	}
}

func TestSignupProviderConfigurationIsBoundedAndClosed(t *testing.T) {
	valid := `[{"id":"github","label":"GitHub","broker_alias":"github"},{"id":"organization","label":"Organization account"}]`
	providers, err := ParseSignupProviders(valid)
	if err != nil || len(providers) != 2 {
		t.Fatalf("valid providers rejected: %v", err)
	}
	invalid := []string{"null", `{}`, valid + `[]`, `[{"id":"github","label":"GitHub","issuer":"https://attacker.invalid"}]`,
		`[{"id":"github","label":"GitHub"},{"id":"github","label":"duplicate"}]`,
		`[{"id":"github","label":"GitHub","broker_alias":"https://attacker.invalid"}]`,
		`[{"id":"github","label":"bad\nlabel"}]`, `[{"id":"github","label":" "}]`, strings.Repeat(" ", 16385)}
	for _, raw := range invalid {
		if _, err := ParseSignupProviders(raw); err == nil {
			t.Fatalf("invalid config accepted: %q", raw)
		}
	}
	many := make([]SignupProvider, 17)
	if ValidateSignupProviders(many) == nil {
		t.Fatal("too many providers accepted")
	}
}
