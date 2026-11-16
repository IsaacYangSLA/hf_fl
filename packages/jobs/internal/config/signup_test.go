package config

import "testing"

func TestSignupProviderSettingsFromTrustedEnvironment(t *testing.T) {
	env := databaseEnv()
	env["HF2L_JOBS_OIDC_SIGNUP_PROVIDERS_JSON"] = `[{"id":"github","label":"GitHub","broker_alias":"github"}]`
	settings, err := FromEnv(lookup(env), "", "database")
	if err != nil || len(settings.SignupProviders) != 1 || settings.SignupProviders[0].BrokerAlias != "github" {
		t.Fatalf("trusted settings: %v", err)
	}
	env["JOBS_OIDC_SIGNUP_PROVIDERS_JSON"] = `[]`
	if _, err := FromEnv(lookup(env), "", "database"); err == nil {
		t.Fatal("conflicting provider aliases accepted")
	}
	delete(env, "JOBS_OIDC_SIGNUP_PROVIDERS_JSON")
	env["HF2L_JOBS_OIDC_SIGNUP_PROVIDERS_JSON"] = `[{"id":"github","label":"GitHub","issuer":"https://untrusted.invalid"}]`
	if _, err := FromEnv(lookup(env), "", "database"); err == nil {
		t.Fatal("caller-selectable issuer accepted")
	}
}
