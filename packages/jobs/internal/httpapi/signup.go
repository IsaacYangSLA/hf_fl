package httpapi

import (
	"html/template"
	"net/http"
	"net/url"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/auth"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

var signupTemplate = template.Must(template.New("signup").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign up · HF²L</title><link rel="stylesheet" href="/dashboard/styles.css"></head>
<body><main id="main"><section class="login-panel"><div class="eyebrow">HF²L participant signup</div>
<h1>Join a federated learning study</h1><p>Use an account from a trusted identity provider. Your provider verifies who you are; HF²L does not collect its password.</p>
{{range .}}<p><a class="button primary" href="{{.SignupURL}}">Continue with {{.Label}}</a></p>{{end}}
<p>After signing in, request to join a study. Org P must approve your request before you can participate. Signing in does not grant access to any study or its jobs.</p>
<p><a href="/dashboard/#studies">Already signed in? Browse studies</a> · <a href="/dashboard/">Back to dashboard</a></p>
</section></main></body></html>`))

func (s *Server) signupPage(w http.ResponseWriter, r *http.Request) error {
	if r.Method != "GET" && r.Method != "HEAD" {
		return domain.Err(405, "http_error")
	}
	if r.URL.RawQuery != "" {
		return domain.Err(422, "invalid_request")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Method == "HEAD" {
		return nil
	}
	return signupTemplate.Execute(w, s.auth.SignupProviders())
}

func (s *Server) signupProviders(w http.ResponseWriter, r *http.Request) error {
	if err := requireMethod(r, "GET"); err != nil {
		return err
	}
	if r.URL.RawQuery != "" {
		return domain.Err(422, "invalid_request")
	}
	return writeJSON(w, 200, map[string]any{"providers": s.auth.SignupProviders()})
}

func (s *Server) signup(w http.ResponseWriter, r *http.Request) error {
	if err := requireMethod(r, "GET"); err != nil {
		return err
	}
	query, err := parseSignupQuery(r)
	if err != nil {
		return err
	}
	start, err := s.auth.BeginSignup(r.Context(), query)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: auth.LoginCookie, Value: start.StateCookie,
		Path: "/", MaxAge: 600, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, start.AuthorizationURL, 303)
	return nil
}

func parseSignupQuery(r *http.Request) (string, error) {
	if len(r.URL.RawQuery) > 1024 {
		return "", domain.Err(422, "invalid_request")
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["provider"]) != 1 || query.Get("provider") == "" {
		return "", domain.Err(422, "invalid_request")
	}
	return query.Get("provider"), nil
}
