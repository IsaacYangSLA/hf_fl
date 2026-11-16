package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/auth"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

// TestStudyBrowserWithRealGoOIDCAndManager uses native authentication and study
// APIs with the embedded dashboard. It never intercepts API responses or starts
// training; only the local identity authority is a test fixture.
func TestStudyBrowserWithRealGoOIDCAndManager(t *testing.T) {
	python := os.Getenv("HF2L_GO_BROWSER_PYTHON")
	if python == "" {
		t.Skip("set HF2L_GO_BROWSER_PYTHON to a Python environment with Playwright and Chromium")
	}
	f := newWebFixture(t, nil, nil)
	_, port, err := net.SplitHostPort(f.http.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	origin := "https://localhost:" + port
	idp := newWebOIDCServer(t, origin+"/auth/callback")
	alice := domain.PrincipalID(idp.server.URL, "alice")
	bob := domain.PrincipalID(idp.server.URL, "bob")
	cfg := auth.Config{OIDC: auth.OIDCConfig{Issuer: idp.server.URL, ClientID: "dashboard", ClientSecret: "test-oidc-client", RedirectURI: origin + "/auth/callback", Audience: "hf2l-jobs"}, SessionSecret: strings.Repeat("b", 40)}
	provider, err := auth.NewOIDCProvider(cfg.OIDC, idp.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	service, err := auth.New(f.db, cfg, provider)
	if err != nil {
		t.Fatal(err)
	}
	f.auth = service
	f.server.auth = service
	f.manager.PlatformOperatorIDs = map[string]bool{}
	if _, err = f.db.Exec(context.Background(), "DELETE FROM jm_project_members WHERE project_id=?", "research"); err != nil {
		t.Fatal(err)
	}
	f.insert("jm_project_members", map[string]any{"project_id": "research", "principal_id": bob, "role": "admin"})
	output := os.Getenv("HF2L_GO_STUDY_BROWSER_ARTIFACTS")
	if output == "" {
		output = t.TempDir()
	}
	if err = os.MkdirAll(output, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-u", "-c", studyBrowserScript, origin, output)
	cmd.Env = os.Environ()
	result, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("native study browser failed: %v\n%s", err, result)
	}
	var report map[string]any
	if err = json.Unmarshal(result, &report); err != nil {
		t.Fatalf("invalid browser report: %v\n%s", err, result)
	}
	if report["approved_principal"] != alice || report["api_interception"] != false {
		t.Fatalf("unexpected browser evidence: %s", result)
	}
	if idp.tokens.Load() != 3 || idp.cookieLeaks.Load() != 0 {
		t.Fatalf("identity boundary: exchanges=%d cookie leaks=%d", idp.tokens.Load(), idp.cookieLeaks.Load())
	}
	if _, err = os.Stat(filepath.Join(output, "study-approved.png")); err != nil {
		t.Fatal(err)
	}
	t.Logf("Study signup, pending denial, withdrawal, rejection, reapplication and approval passed against real Go APIs. Evidence: %s", output)
}

const studyBrowserScript = `
import asyncio, json, pathlib, sys, urllib.parse
from playwright.async_api import async_playwright, expect

origin, output = sys.argv[1:]
output = pathlib.Path(output)

async def main():
    errors = []
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True, args=["--disable-dev-shm-usage"])
        owner = await browser.new_context(ignore_https_errors=True, service_workers="block")
        applicant = await browser.new_context(ignore_https_errors=True, service_workers="block")
        owner_page = await owner.new_page()
        alice_page = await applicant.new_page()
        for page in (owner_page, alice_page):
            page.set_default_timeout(20000)
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("request", lambda request: errors.append("unexpected remote request") if urllib.parse.urlparse(request.url).hostname not in {"localhost", "127.0.0.1"} else None)

        async def sign_in(page, subject, signup=False):
            await page.goto(origin + "/dashboard/")
            await page.locator("#login-panel").wait_for(state="visible")
            if signup:
                await page.locator("#signup-link").click()
                await page.locator('a[href^="/auth/signup?provider="]').first.click()
            else:
                await page.locator("#login-link").click()
            await page.locator('input[name="username"]').fill(subject)
            await page.get_by_role("button", name="Sign in", exact=True).click()
            await page.wait_for_url(origin + "/dashboard/")
            await page.locator("#application").wait_for(state="visible")

        async def open_research(page):
            await page.get_by_role("link", name="Studies", exact=True).click()
            await page.get_by_role("link", name="View study", exact=True).first.click()
            await page.locator("#studies-panel").wait_for(state="visible")

        async def refresh(page):
            await page.locator("#refresh-button").click()
            await expect(page.locator("#refresh-button")).to_be_enabled()

        async def request_join():
            form = alice_page.locator("#study-request-form")
            await form.locator('input[name="participant_id"]').fill("alice")
            await form.locator('textarea[name="message"]').fill("Alice's organization would like to join. <b>This is plain text.</b>")
            await form.get_by_role("button", name="Request to join", exact=True).or_(form.get_by_role("button", name="Send a new request", exact=True)).click()
            await alice_page.locator("#study-participation .badge.pending").wait_for()

        async def review(action, reason):
            await refresh(owner_page)
            item = owner_page.locator(".study-application").filter(has=owner_page.locator(".badge.pending"))
            await item.locator('textarea[name="reason"]').fill(reason)
            await item.get_by_role("button", name=action, exact=True).click()
            await expect(owner_page.locator("#refresh-button")).to_be_enabled()

        await sign_in(owner_page, "bob")
        await open_research(owner_page)
        settings = owner_page.locator("#study-settings-form")
        await settings.locator('textarea[name="description"]').fill("A jointly trained model. <img src=x onerror=alert(1)>")
        await settings.locator('input[name="registration_open"]').check()
        await settings.get_by_role("button", name="Enable study signup", exact=True).click()
        await settings.get_by_role("button", name="Save signup settings", exact=True).wait_for()
        assert await owner_page.locator("#studies-panel img").count() == 0

        await sign_in(alice_page, "alice", signup=True)
        assert await alice_page.locator("#create-button").is_hidden()
        catalog = await alice_page.request.get(origin + "/api/jobs/v1/catalog")
        assert catalog.status == 200 and (await catalog.json())["projects"] == []
        await open_research(alice_page)
        await request_join()
        denied = await alice_page.request.get(origin + "/api/jobs/v1/studies/research/applications")
        assert denied.status in (403, 404)
        assert await alice_page.locator("#study-applications").count() == 0
        assert await alice_page.locator("#studies-panel b").count() == 0
        await alice_page.screenshot(path=str(output / "study-pending.png"), full_page=True)

        await alice_page.get_by_role("button", name="Withdraw request", exact=True).click()
        await alice_page.locator("#study-participation .badge.withdrawn").wait_for()
        await request_join()
        await review("Reject", "Please clarify the study agreement.")
        await refresh(alice_page)
        await alice_page.locator("#study-participation .badge.rejected").wait_for()
        assert "Please clarify" in await alice_page.locator("#study-participation").inner_text()
        await request_join()
        await review("Approve", "Approved for this study.")
        await refresh(alice_page)
        await alice_page.locator("#study-participation .badge.approved").wait_for()
        assert await alice_page.locator("#create-button").is_hidden()
        assert await alice_page.locator("#study-request-form").count() == 0
        final_catalog = await alice_page.request.get(origin + "/api/jobs/v1/catalog")
        assert (await final_catalog.json())["projects"] == []
        membership = await alice_page.request.get(origin + "/api/jobs/v1/studies/research/application")
        assert membership.status == 200
        application = (await membership.json())["application"]
        assert application["status"] == "approved" and application["participant_id"] == "alice"
        missing_csrf = await alice_page.request.post(origin + "/api/jobs/v1/studies/research/applications", data={"participant_id": "other", "message": ""})
        assert missing_csrf.status == 403
        await settings.locator('input[name="registration_open"]').uncheck()
        await settings.get_by_role("button", name="Save signup settings", exact=True).click()
        await expect(owner_page.locator("#refresh-button")).to_be_enabled()
        await refresh(alice_page)
        await alice_page.locator("#study-participation .badge.approved").wait_for()
        assert "Signup is closed" in await alice_page.locator("#studies-panel").inner_text()
        await alice_page.screenshot(path=str(output / "study-approved.png"), full_page=True)

        # An unsaved Org P form must not retain private review data after the
        # shared browser session changes in another tab. No API is intercepted.
        await settings.locator('textarea[name="description"]').fill("Unsaved Org P draft")
        switch_page = await owner.new_page()
        switch_page.set_default_timeout(20000)
        await switch_page.goto(origin + "/auth/login")
        await switch_page.locator('input[name="username"]').fill("alice")
        await switch_page.get_by_role("button", name="Sign in", exact=True).click()
        await switch_page.wait_for_url(origin + "/dashboard/")
        await owner_page.bring_to_front()
        await owner_page.locator("#login-panel").wait_for(state="visible", timeout=25000)
        assert "account changed" in await owner_page.locator("#login-panel").inner_text()
        assert await owner_page.locator("#studies-panel").inner_text() == ""
        assert await owner_page.locator("#study-applications").count() == 0
        await switch_page.close()
        assert errors == [], errors
        print(json.dumps({"approved_principal": application["principal_id"], "api_interception": False, "browser_errors": errors, "workflow": ["signup", "pending", "withdrawn", "rejected", "reapplied", "approved"]}))
        await owner.close()
        await applicant.close()
        await browser.close()

asyncio.run(main())
`

// TestStudyBrowserRecoversExpiredPages advances only the manager's test clock.
// Study API responses still come from the native production handlers, including
// their real signed-cursor validation; the browser does not intercept them.
func TestStudyBrowserRecoversExpiredPages(t *testing.T) {
	python := os.Getenv("HF2L_GO_BROWSER_PYTHON")
	if python == "" {
		t.Skip("set HF2L_GO_BROWSER_PYTHON to a Python environment with Playwright and Chromium")
	}
	f := newWebFixture(t, nil, nil)
	var shift atomic.Int64
	f.manager.Clock = func() time.Time { return time.Now().Add(time.Duration(shift.Load()) * time.Second) }
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_fixture/advance-manager-clock" && r.Method == http.MethodPost {
			shift.Add(3601)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		f.server.ServeHTTP(w, r)
	}))
	t.Cleanup(func() { fixture.CloseClientConnections(); fixture.Close() })
	_, port, err := net.SplitHostPort(fixture.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	origin := "https://localhost:" + port
	idp := newWebOIDCServer(t, origin+"/auth/callback")
	bob := domain.PrincipalID(idp.server.URL, "bob")
	cfg := auth.Config{OIDC: auth.OIDCConfig{Issuer: idp.server.URL, ClientID: "dashboard", ClientSecret: "test-oidc-client", RedirectURI: origin + "/auth/callback", Audience: "hf2l-jobs"}, SessionSecret: strings.Repeat("p", 40)}
	provider, err := auth.NewOIDCProvider(cfg.OIDC, idp.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	service, err := auth.New(f.db, cfg, provider)
	if err != nil {
		t.Fatal(err)
	}
	f.auth = service
	f.server.auth = service
	f.manager.PlatformOperatorIDs = map[string]bool{}
	if _, err = f.db.Exec(context.Background(), "DELETE FROM jm_project_members WHERE project_id=?", "research"); err != nil {
		t.Fatal(err)
	}
	f.insert("jm_project_members", map[string]any{"project_id": "research", "principal_id": bob, "role": "admin"})
	for index := 0; index < 51; index++ {
		id := fmt.Sprintf("z-study-%03d", index)
		f.insert("jm_projects", map[string]any{"id": id, "name": id})
		f.insert("jm_project_members", map[string]any{"project_id": id, "principal_id": bob, "role": "admin"})
	}
	if _, err = f.manager.PutStudySettings(context.Background(), bob, "research", "Cursor recovery study", true, 1, "browser-enable"); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 51; index++ {
		subject := fmt.Sprintf("test-applicant-%03d", index)
		actor := domain.PrincipalID(idp.server.URL, subject)
		if _, err = f.manager.ApplyToStudy(context.Background(), actor, "research", subject, "Test fixture application", subject); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-u", "-c", studyCursorBrowserScript, origin)
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("study cursor browser failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), `"native_cursor_expiry_recovered": true`) {
		t.Fatalf("missing native cursor recovery evidence: %s", output)
	}
	if shift.Load() != 7202 {
		t.Fatalf("expected two controlled expiry transitions, got %d", shift.Load())
	}
	t.Log("Actual native study-list and application-list cursors expired and the dashboard recovered to each first page")
}

const studyCursorBrowserScript = `
import asyncio, json, sys
from playwright.async_api import async_playwright, expect
origin = sys.argv[1]

async def main():
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True, args=["--disable-dev-shm-usage"])
        context = await browser.new_context(ignore_https_errors=True, service_workers="block")
        page = await context.new_page()
        page.set_default_timeout(20000)
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        await page.goto(origin + "/dashboard/")
        await page.locator("#login-link").click()
        await page.locator('input[name="username"]').fill("bob")
        await page.get_by_role("button", name="Sign in", exact=True).click()
        await page.wait_for_url(origin + "/dashboard/")
        await page.get_by_role("link", name="Studies", exact=True).click()
        await page.get_by_role("button", name="More studies", exact=True).click()
        await expect(page.get_by_role("button", name="Previous studies", exact=True)).to_be_enabled()
        await expect(page.get_by_role("button", name="More studies", exact=True)).to_be_disabled()
        advance = await page.request.post(origin + "/_fixture/advance-manager-clock")
        assert advance.status == 204
        await page.locator("#refresh-button").click()
        await expect(page.get_by_role("button", name="Previous studies", exact=True)).to_be_disabled()
        await expect(page.get_by_role("button", name="More studies", exact=True)).to_be_enabled()
        await page.get_by_role("link", name="View study", exact=True).first.click()
        await page.locator("#study-applications").wait_for()
        await page.get_by_role("button", name="More requests", exact=True).click()
        await expect(page.get_by_role("button", name="Previous requests", exact=True)).to_be_enabled()
        await expect(page.get_by_role("button", name="More requests", exact=True)).to_be_disabled()
        advance = await page.request.post(origin + "/_fixture/advance-manager-clock")
        assert advance.status == 204
        await page.locator("#refresh-button").click()
        await expect(page.get_by_role("button", name="Previous requests", exact=True)).to_be_disabled()
        await expect(page.get_by_role("button", name="More requests", exact=True)).to_be_enabled()
        assert await page.locator(".study-application").count() == 50
        assert await page.locator("#page-error").is_hidden()
        assert errors == [], errors
        print(json.dumps({"native_cursor_expiry_recovered": True, "api_interception": False}))
        await context.close()
        await browser.close()
asyncio.run(main())
`
