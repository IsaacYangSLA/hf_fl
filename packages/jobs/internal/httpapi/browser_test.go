package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/auth"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/manager"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/scheduler"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
	"github.com/golang-jwt/jwt/v5"
)

type webAuthorization struct {
	state, nonce, challenge, redirect, subject string
	used                                       bool
}
type webOIDCServer struct {
	server                              *httptest.Server
	key                                 *rsa.PrivateKey
	redirect                            string
	mu                                  sync.Mutex
	requests                            map[string]webAuthorization
	codes                               map[string]webAuthorization
	access                              map[string]string
	tokens, introspections, cookieLeaks atomic.Int64
}

func newWebOIDCServer(t *testing.T, redirect string) *webOIDCServer {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	p := &webOIDCServer{key: key, redirect: redirect, requests: map[string]webAuthorization{}, codes: map[string]webAuthorization{}, access: map[string]string{}}
	p.server = httptest.NewTLSServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.server.Close)
	return p
}
func (p *webOIDCServer) sign(claims jwt.MapClaims, typ string) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "browser-key"
	tok.Header["typ"] = typ
	return tok.SignedString(p.key)
}
func webHalfHash(value string) string {
	d := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(d[:16])
}
func (p *webOIDCServer) serve(w http.ResponseWriter, r *http.Request) {
	for _, c := range r.Cookies() {
		if c.Name == auth.LoginCookie || c.Name == auth.SessionCookie {
			p.cookieLeaks.Add(1)
		}
	}
	answer := func(v any) { w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(v) }
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		issuer := p.server.URL
		answer(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks", "introspection_endpoint": issuer + "/introspect", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "code_challenge_methods_supported": []string{"S256"}})
	case "/jwks":
		answer(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "browser-key", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(p.key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.E)).Bytes())}}})
	case "/authorize":
		q := r.URL.Query()
		if r.Method != "GET" || q.Get("redirect_uri") != p.redirect || q.Get("client_id") != "dashboard" || q.Get("response_type") != "code" || q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 {
			http.Error(w, "invalid authorization request", 400)
			return
		}
		entry := webAuthorization{state: q.Get("state"), nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
		p.mu.Lock()
		p.requests[entry.state] = entry
		p.mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, "<!doctype html><html lang=\"en\"><title>Test identity provider</title><h1>Test identity provider</h1><form method=\"post\" action=\"/login\"><input type=\"hidden\" name=\"state\" value=\""+html.EscapeString(entry.state)+"\"><label>Username<input name=\"username\" required></label><button type=\"submit\">Sign in</button></form></html>")
	case "/login":
		if r.Method != "POST" || r.ParseForm() != nil {
			http.Error(w, "invalid login", 400)
			return
		}
		subject := r.PostForm.Get("username")
		if subject != "alice" && subject != "bob" {
			http.Error(w, "unknown test identity", 401)
			return
		}
		p.mu.Lock()
		entry, ok := p.requests[r.PostForm.Get("state")]
		delete(p.requests, r.PostForm.Get("state"))
		if !ok {
			p.mu.Unlock()
			http.Error(w, "invalid state", 400)
			return
		}
		entry.subject = subject
		code := domain.NewID()
		p.codes[code] = entry
		p.mu.Unlock()
		http.Redirect(w, r, entry.redirect+"?"+url.Values{"code": {code}, "state": {entry.state}}.Encode(), 303)
	case "/token":
		client, secret, ok := r.BasicAuth()
		if r.Method != "POST" || !ok || client != "dashboard" || secret != "test-oidc-client" || r.ParseForm() != nil {
			http.Error(w, "invalid client", 401)
			return
		}
		code := r.PostForm.Get("code")
		p.mu.Lock()
		entry, ok := p.codes[code]
		challenge := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || entry.used || r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("client_id") != "dashboard" || r.PostForm.Get("redirect_uri") != entry.redirect || base64.RawURLEncoding.EncodeToString(challenge[:]) != entry.challenge {
			p.mu.Unlock()
			http.Error(w, "invalid authorization code or PKCE", 400)
			return
		}
		entry.used = true
		p.codes[code] = entry
		p.mu.Unlock()
		now := time.Now().Unix()
		access, e := p.sign(jwt.MapClaims{"iss": p.server.URL, "sub": entry.subject, "aud": "hf2l-jobs", "iat": now, "exp": now + 3600, "scope": "jobs"}, "at+jwt")
		if e != nil {
			http.Error(w, "signing failed", 500)
			return
		}
		id, e := p.sign(jwt.MapClaims{"iss": p.server.URL, "sub": entry.subject, "aud": "dashboard", "iat": now, "exp": now + 3600, "nonce": entry.nonce, "sid": "test-" + entry.subject, "at_hash": webHalfHash(access), "c_hash": webHalfHash(code)}, "JWT")
		if e != nil {
			http.Error(w, "signing failed", 500)
			return
		}
		p.mu.Lock()
		p.access[access] = entry.subject
		p.mu.Unlock()
		p.tokens.Add(1)
		answer(map[string]any{"access_token": access, "id_token": id, "token_type": "Bearer", "expires_in": 3600})
	case "/introspect":
		client, secret, ok := r.BasicAuth()
		if r.Method != "POST" || !ok || client != "dashboard" || secret != "test-oidc-client" || r.ParseForm() != nil {
			http.Error(w, "invalid client", 401)
			return
		}
		p.mu.Lock()
		subject, ok := p.access[r.PostForm.Get("token")]
		p.mu.Unlock()
		p.introspections.Add(1)
		answer(map[string]any{"active": ok, "sub": subject, "iss": p.server.URL, "client_id": "dashboard", "aud": "hf2l-jobs", "scope": "jobs", "exp": time.Now().Add(time.Hour).Unix()})
	default:
		http.NotFound(w, r)
	}
}

// TestWebBrowser uses the real Go OIDC client, API, SQL manager and dashboard.
// Only the identity authority and explicit lifecycle fixture inputs are local
// test components. It is not a sandbox execution qualification test.
func TestWebBrowserWithRealGoOIDCAndManager(t *testing.T) {
	python := os.Getenv("HF2L_GO_BROWSER_PYTHON")
	if python == "" {
		t.Skip("set HF2L_GO_BROWSER_PYTHON to a Python environment with Playwright and Chromium")
	}
	f := newWebFixture(t, nil, nil)
	_, port, e := net.SplitHostPort(f.http.Listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	origin := "https://localhost:" + port
	idp := newWebOIDCServer(t, origin+"/auth/callback")
	alice := domain.PrincipalID(idp.server.URL, "alice")
	bob := domain.PrincipalID(idp.server.URL, "bob")
	cfg := auth.Config{OIDC: auth.OIDCConfig{Issuer: idp.server.URL, ClientID: "dashboard", ClientSecret: "test-oidc-client", RedirectURI: origin + "/auth/callback", Audience: "hf2l-jobs"}, SessionSecret: strings.Repeat("b", 40), PlatformOperatorIDs: []string{alice}}
	provider, e := auth.NewOIDCProvider(cfg.OIDC, idp.server.Client())
	if e != nil {
		t.Fatal(e)
	}
	service, e := auth.New(f.db, cfg, provider)
	if e != nil {
		t.Fatal(e)
	}
	f.auth = service
	f.server.auth = service
	f.manager.PlatformOperatorIDs = map[string]bool{alice: true}
	for _, id := range []string{alice, bob} {
		f.insert("jm_project_members", map[string]any{"project_id": "research", "principal_id": id, "role": "submitter"})
	}
	raw, e := json.Marshal(webSpec("Bob private federation"))
	if e != nil {
		t.Fatal(e)
	}
	spec, e := domain.DecodeJobSpec(raw)
	if e != nil {
		t.Fatal(e)
	}
	foreign, e := f.manager.CreateJob(context.Background(), bob, spec, "browser-bob")
	if e != nil {
		t.Fatal(e)
	}
	output := os.Getenv("HF2L_GO_BROWSER_ARTIFACTS")
	if output == "" {
		output = t.TempDir()
	}
	if e = os.MkdirAll(output, 0700); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-u", "-c", webBrowserScript, origin, foreign["id"].(string), bob, output)
	cmd.Env = []string{}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "HF2L_GO_HTTP_TEST_DATABASE_URL=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	stdin, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	done := false
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var createdID string
	sc := scheduler.New(f.db)
	for scanner.Scan() {
		var msg map[string]any
		if e = json.Unmarshal(scanner.Bytes(), &msg); e != nil {
			cancel()
			_ = cmd.Wait()
			t.Fatalf("invalid browser driver result: %s", scanner.Text())
		}
		event, _ := msg["event"].(string)
		var stepErr error
		switch event {
		case "admit":
			createdID, _ = msg["job_id"].(string)
			row, err := f.db.One(context.Background(), "SELECT * FROM jm_jobs WHERE id=?", createdID)
			if err != nil || row == nil || row["creator_id"] != alice || row["state"] != "QUEUED" {
				stepErr = fmt.Errorf("browser did not create an authorized queued job: %v", err)
				break
			}
			admissions, err := sc.Schedule(context.Background(), 100)
			stepErr = err
			found := false
			for _, a := range admissions {
				if a.JobID == createdID {
					found = true
				}
			}
			if stepErr == nil && !found {
				stepErr = fmt.Errorf("Go scheduler did not admit browser-created job")
			}
		case "require_introspection":
			_, stepErr = f.db.Exec(context.Background(), "UPDATE jm_auth_sessions SET checked_at=? WHERE issuer=? AND subject=? AND revoked_at IS NULL", time.Now().UTC().Add(-16*time.Minute), idp.server.URL, "alice")
		case "introspection_checked":
			if idp.introspections.Load() < 1 {
				stepErr = fmt.Errorf("real introspection endpoint was not called")
			}
		case "reader_granted":
			member, err := f.db.One(context.Background(), "SELECT role FROM jm_job_members WHERE job_id=? AND principal_id=?", createdID, bob)
			stepErr = err
			if err == nil && (member == nil || member["role"] != "reader") {
				stepErr = fmt.Errorf("browser membership grant did not persist")
			}
		case "complete_fixture":
			// The browser test injects a terminal fixture; no training was started.
			// Allocation release still requires the real persisted fencing proofs.
			allocations, err := f.db.All(context.Background(), "SELECT * FROM jm_allocations WHERE job_id=? AND released_at IS NULL", createdID)
			if err != nil {
				stepErr = err
				break
			}
			for _, a := range allocations {
				f.update("jm_attempts", map[string]any{"id": a["attempt_id"]}, map[string]any{"termination_confirmed": true, "revocation_confirmed": true, "state": "SUCCEEDED"})
				f.update("jm_allocations", map[string]any{"id": a["id"]}, map[string]any{"termination_confirmed": true})
				if err = sc.Release(context.Background(), a["id"].(string)); err != nil {
					stepErr = err
					break
				}
			}
			if stepErr != nil {
				break
			}
			stepErr = f.db.WithTx(context.Background(), true, func(tx *store.Tx) error {
				row, err := tx.One(context.Background(), "SELECT version FROM jm_jobs WHERE id=?"+tx.ForUpdate(), createdID)
				if err != nil {
					return err
				}
				version, ok := row["version"].(int64)
				if !ok {
					return fmt.Errorf("invalid stored job version")
				}
				now := time.Now().UTC()
				if err = tx.Update(context.Background(), "jm_jobs", map[string]any{"id": createdID}, map[string]any{"state": "SUCCEEDED", "phase": "completed", "current_round": int64(2), "version": version + 1, "terminated_at": now, "updated_at": now}); err != nil {
					return err
				}
				return manager.AppendEvent(context.Background(), tx, createdID, "test.completed_fixture", "browser-test", map[string]any{"fixture": true}, now)
			})
		case "done":
			done = true
		default:
			stepErr = fmt.Errorf("unexpected browser stage %q", event)
		}
		reply := map[string]any{"ok": stepErr == nil}
		if stepErr != nil {
			reply["error"] = stepErr.Error()
		}
		encoded, _ := json.Marshal(reply)
		_, _ = fmt.Fprintln(stdin, string(encoded))
		if stepErr != nil {
			cancel()
			_ = cmd.Wait()
			t.Fatalf("browser stage %s: %v\n%s", event, stepErr, stderr.String())
		}
	}
	_ = stdin.Close()
	e = cmd.Wait()
	if scanner.Err() != nil {
		t.Fatal(scanner.Err())
	}
	if e != nil || !done {
		t.Fatalf("real Go-backed browser failed: %v; done=%v\n%s", e, done, stderr.String())
	}
	if idp.tokens.Load() != 3 || idp.cookieLeaks.Load() != 0 {
		t.Fatalf("OIDC flow or cookie boundary incorrect: token exchanges=%d, manager-cookie leaks=%d", idp.tokens.Load(), idp.cookieLeaks.Load())
	}
	result, e := os.ReadFile(filepath.Join(output, "browser-result.json"))
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("Real Go-backed browser passed; %d authorization-code exchanges, %d introspection requests. Artifacts: %s", idp.tokens.Load(), idp.introspections.Load(), output)
	if !strings.Contains(string(result), "no API interception") {
		t.Fatal("missing browser evidence")
	}
}

const webBrowserScript = "import asyncio, json, os, pathlib, sys, urllib.parse\nfrom playwright.async_api import async_playwright\n\norigin, foreign_job, bob_principal, output = sys.argv[1:]\noutput = pathlib.Path(output)\noutput.mkdir(parents=True, exist_ok=True)\n\ndef stage(event, **values):\n    print(json.dumps({\"event\": event, **values}), flush=True)\n    reply = sys.stdin.readline()\n    if not reply:\n        raise AssertionError(\"Go fixture driver ended\")\n    response = json.loads(reply)\n    assert response.get(\"ok\") is True, response\n\nasync def main():\n    errors, captures = [], []\n    async with async_playwright() as pw:\n        browser = await pw.chromium.launch(headless=True, args=[\"--disable-dev-shm-usage\"])\n        # This context accepts only the two ephemeral self-signed test servers.\n        # Cryptographic trust/purpose behavior is tested by the Go TLS tests.\n        context = await browser.new_context(ignore_https_errors=True,\n            viewport={\"width\": 1440, \"height\": 1000}, service_workers=\"block\")\n        page = await context.new_page()\n        page.set_default_timeout(15000)\n        page.on(\"pageerror\", lambda error: errors.append(str(error)))\n        page.on(\"request\", lambda request: errors.append(\"unexpected remote request\")\n            if urllib.parse.urlparse(request.url).hostname not in {\"localhost\", \"127.0.0.1\"}\n            else None)\n\n        async def capture(name):\n            await page.screenshot(path=str(output / (name + \".png\")), full_page=True)\n            captures.append(name + \".png\")\n\n        async def signin(subject):\n            await page.locator(\"#login-panel\").wait_for(state=\"visible\")\n            await page.locator(\"#login-link\").click()\n            await page.locator('input[name=\"username\"]').fill(subject)\n            await page.get_by_role(\"button\", name=\"Sign in\", exact=True).click()\n            await page.wait_for_url(origin + \"/dashboard/\")\n            await page.locator(\"#application\").wait_for(state=\"visible\")\n            await page.locator(\"#create-button\").wait_for(state=\"visible\")\n            await page.wait_for_function(\"!document.querySelector('#create-button').disabled\")\n            assert subject in await page.locator(\"#identity\").inner_text()\n\n        await page.goto(origin + \"/dashboard/\")\n        await page.locator(\"#login-panel\").wait_for(state=\"visible\")\n        await capture(\"01-signed-out\")\n        await signin(\"alice\")\n        await capture(\"02-authenticated\")\n        await page.locator(\"#create-button\").click()\n        form = page.locator(\"#create-form\")\n        await form.locator('input[name=\"display_name\"]').fill(\"Browser-created federation\")\n        await form.locator('select[name=\"source_id\"]').select_option(\"approved\")\n        await form.locator('input[name=\"source_commit\"]').fill(\"a\" * 40)\n        await form.locator('select[name=\"runtime_image\"]').select_option(\"cpu-image\")\n        await form.locator('input[name=\"plugin\"]').fill(\"lenet\")\n        await form.locator('select[name=\"pool_id\"]').select_option(\"cpu\")\n        await form.locator('input[name=\"target_final_round\"]').fill(\"2\")\n        await form.locator('input[name=\"max_duration_minutes\"]').fill(\"10\")\n        await form.locator('input[name=\"memory_mib\"]').fill(\"1\")\n        await form.locator('input[name=\"disk_mib\"]').fill(\"1\")\n        for checkbox in await page.locator(\"#participant-bindings input[type=checkbox]\").all():\n            await checkbox.check()\n        await capture(\"03-creation-form\")\n        await page.locator(\"#submit-create\").click()\n        await page.wait_for_url(\"**#job/*\")\n        job_id = urllib.parse.urlparse(page.url).fragment.split(\"/\", 1)[1].split(\"?\", 1)[0]\n        await page.locator(\"#detail-panel\").wait_for(state=\"visible\")\n        assert \"Browser-created federation\" in await page.locator(\"#page-title\").inner_text()\n\n        await page.locator('a[data-view=\"queued\"]').click()\n        await page.locator(\"#jobs-content .job-name\",\n            has_text=\"Browser-created federation\").wait_for()\n        assert \"Bob private federation\" not in await page.locator(\"#jobs-content\").inner_text()\n        await capture(\"04-queued\")\n        stage(\"admit\", job_id=job_id)\n        await page.locator('a[data-view=\"current\"]').click()\n        await page.locator(\"#jobs-content .job-name\",\n            has_text=\"Browser-created federation\").wait_for()\n        await capture(\"05-current\")\n\n        stage(\"require_introspection\")\n        response = await page.request.get(origin + \"/auth/session\")\n        assert response.status == 200 and (await response.json())[\"authenticated\"]\n        stage(\"introspection_checked\")\n\n        await page.goto(origin + \"/dashboard/#job/\" + foreign_job)\n        await page.locator(\"#page-error\").wait_for(state=\"visible\")\n        assert \"Bob private federation\" not in await page.locator(\"#main\").inner_text()\n        await capture(\"06-foreign-job-denied\")\n        await page.goto(origin + \"/dashboard/#job/\" + job_id)\n        await page.locator(\"#detail-panel\").wait_for(state=\"visible\")\n        await page.locator('a[href$=\"?tab=access\"]').click()\n        await page.get_by_role(\"button\", name=\"Grant access\", exact=True).click()\n        await page.locator('#member-form input[name=\"principal_id\"]').fill(bob_principal)\n        await page.locator('#member-form select[name=\"role\"]').select_option(\"reader\")\n        await page.locator(\"#submit-member\").click()\n        await page.locator(\"#detail-panel td\", has_text=bob_principal).wait_for()\n        stage(\"reader_granted\", job_id=job_id)\n\n        await page.locator(\"#logout-button\").click()\n        await page.locator(\"#login-panel\").wait_for(state=\"visible\")\n        response = await page.request.get(origin + \"/auth/session\")\n        assert not (await response.json())[\"authenticated\"]\n        await signin(\"bob\")\n        assert await page.locator(\"#operations-link\").is_hidden()\n        await page.goto(origin + \"/dashboard/#job/\" + job_id)\n        await page.locator(\"#detail-panel\").wait_for(state=\"visible\")\n        assert await page.locator(\"#detail-panel\").get_by_role(\n            \"button\", name=\"Cancel\", exact=True).count() == 0\n        assert await page.locator(\"#detail-panel\").get_by_role(\n            \"button\", name=\"Grant access\", exact=True).count() == 0\n        await capture(\"07-reader-view\")\n        await page.locator(\"#logout-button\").click()\n        await page.locator(\"#login-panel\").wait_for(state=\"visible\")\n        await signin(\"alice\")\n\n        stage(\"complete_fixture\", job_id=job_id)\n        await page.locator('a[data-view=\"history\"]').click()\n        await page.locator(\"#jobs-content .job-name\",\n            has_text=\"Browser-created federation\").wait_for()\n        await capture(\"08-history\")\n        await page.locator(\"#jobs-content .job-name\",\n            has_text=\"Browser-created federation\").click()\n        await page.locator(\"#detail-panel\").wait_for(state=\"visible\")\n        assert \"Succeeded\" in await page.locator(\"#detail-panel\").inner_text()\n        await capture(\"09-terminal-detail\")\n        await page.locator(\"#logout-button\").click()\n        await page.locator(\"#login-panel\").wait_for(state=\"visible\")\n        response = await page.request.get(origin + \"/auth/session\")\n        assert not (await response.json())[\"authenticated\"]\n        assert errors == [], errors\n        report = {\"mode\": \"real Go manager/auth/SQL and signed local OIDC provider; no API interception\",\n            \"browser_errors\": errors, \"screenshots\": captures,\n            \"created_job_id\": job_id, \"database_transitions\": \"explicit test fixture inputs, not real training\"}\n        (output / \"browser-result.json\").write_text(json.dumps(report, indent=2) + \"\\n\")\n        stage(\"done\", job_id=job_id, screenshots=len(captures))\n        await context.close()\n        await browser.close()\n\nasyncio.run(main())\n"
