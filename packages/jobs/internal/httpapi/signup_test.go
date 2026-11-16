package httpapi

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/auth"
)

func TestPublicSignupPageAndProviderChoices(t *testing.T) {
	f := newWebFixture(t, nil, nil)
	f.auth.Config.SignupProviders = []auth.SignupProvider{{ID: "organization", Label: `Example <script>alert(1)</script>`}}
	response := f.raw("GET", "/signup", nil, nil, nil)
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != 200 || !strings.Contains(response.Header.Get("Content-Type"), "text/html") ||
		strings.Contains(string(body), "<script>") || !strings.Contains(string(body), "&lt;script&gt;") ||
		!strings.Contains(string(body), "Org P must approve") || strings.Contains(string(body), "access_token") {
		t.Fatalf("unsafe signup page: status=%d body=%s", response.StatusCode, body)
	}
	result := webJSON(t, f.raw("GET", "/auth/providers", nil, nil, nil), 200)
	choices := result["providers"].([]any)
	if len(choices) != 1 || choices[0].(map[string]any)["signup_url"] != "/auth/signup?provider=organization" {
		t.Fatal(result)
	}
	response = f.raw("GET", "/auth/signup?provider=organization", nil, nil, nil)
	defer response.Body.Close()
	if response.StatusCode != 303 {
		t.Fatalf("signup did not start login: %d", response.StatusCode)
	}
	target, _ := url.Parse(response.Header.Get("Location"))
	if target.Query().Get("code_challenge_method") != "S256" || target.Query().Get("state") == "" {
		t.Fatal("signup lost login protections")
	}
	cookies := response.Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].Name != auth.LoginCookie {
		t.Fatal("signup cookie protection missing")
	}
}

func TestSignupRejectsUnknownQueriesAndUntrustedProviders(t *testing.T) {
	f := newWebFixture(t, nil, nil)
	cases := []struct {
		path, code string
		status     int
	}{
		{"/auth/signup?provider=organization&provider=github", "invalid_request", 422},
		{"/auth/signup?provider=organization&issuer=https://attacker.invalid", "invalid_request", 422},
		{"/auth/signup?provider=https://attacker.invalid", "invalid_signup_provider", 422},
		{"/auth/signup?provider=unlisted", "signup_provider_not_found", 404},
		{"/auth/signup", "invalid_request", 422},
		{"/auth/providers?issuer=bad", "invalid_request", 422},
		{"/signup?redirect=https://attacker.invalid", "invalid_request", 422},
	}
	for _, test := range cases {
		t.Run(test.path, func(t *testing.T) { webError(t, f.raw("GET", test.path, nil, nil, nil), test.status, test.code) })
	}
	webError(t, f.raw("POST", "/auth/signup?provider=organization", nil, nil, nil), 405, "http_error")
	webError(t, f.raw("POST", "/signup", nil, nil, nil), 405, "http_error")
	webError(t, f.raw("GET", Prefix+"/jobs", nil, nil, nil), 401, "authentication_required")
}
