package httpapi

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/auth"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

func TestStudyCreatorBrowserAuthorizationAndRetry(t *testing.T) {
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
	original := f.http.Config.Handler
	f.http.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/_fixture/study-creator/") && r.Method == "POST" {
			now := time.Now().UTC()
			_, err := f.db.Exec(r.Context(), "INSERT INTO jm_study_creators (principal_id,enabled,created_at,updated_at) VALUES (?,?,?,?) ON CONFLICT (principal_id) DO UPDATE SET enabled=excluded.enabled,updated_at=excluded.updated_at", alice, strings.HasSuffix(r.URL.Path, "/enable"), now, now)
			if err != nil {
				http.Error(w, "fixture failure", 500)
				return
			}
			w.WriteHeader(204)
			return
		}
		original.ServeHTTP(w, r)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-u", "-c", studyCreatorBrowserScript, origin)
	result, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("creator browser: %v\n%s", err, result)
	}
	if !strings.Contains(string(result), "creator_browser_passed") {
		t.Fatal(string(result))
	}
	t.Log(string(result))
}

const studyCreatorBrowserScript = `
import asyncio, json, sys
from playwright.async_api import async_playwright, expect
origin=sys.argv[1]

async def main():
    errors=[]
    async with async_playwright() as pw:
        browser=await pw.chromium.launch(headless=True,args=["--disable-dev-shm-usage"])
        creator=await browser.new_context(ignore_https_errors=True,service_workers="block")
        regular=await browser.new_context(ignore_https_errors=True,service_workers="block")
        page=await creator.new_page(); other=await regular.new_page()
        for item in (page,other):
            item.set_default_timeout(20000)
            item.on("pageerror",lambda error: errors.append(str(error)))
        async def sign_in(item,subject):
            await item.goto(origin+"/dashboard/")
            await item.locator("#login-link").click()
            await item.locator('input[name="username"]').fill(subject)
            await item.get_by_role("button",name="Sign in",exact=True).click()
            await item.wait_for_url(origin+"/dashboard/")
            await item.locator("#application").wait_for(state="visible")
            await item.get_by_role("link",name="Studies",exact=True).click()
            await item.locator("#studies-panel").wait_for(state="visible")
        await sign_in(other,"bob")
        await expect(other.locator("#create-study-button")).to_be_hidden()
        ordinary=await (await other.request.get(origin+"/auth/session")).json()
        assert ordinary["can_create_study"] is False
        denied=await other.request.post(origin+"/api/jobs/v1/studies",data={"name":"Forbidden"},headers={"Origin":origin,"X-CSRF-Token":ordinary["csrf_token"],"Idempotency-Key":"browser-denied"})
        assert denied.status==403
        await sign_in(page,"alice")
        await page.request.post(origin+"/_fixture/study-creator/enable")
        await page.locator("#refresh-button").click()
        await expect(page.locator("#create-study-button")).to_be_visible()
        await page.locator("#create-study-button").click()
        form=page.locator("#create-study-form")
        assert await form.locator("input").count()==1
        name="Creator <img src=x onerror=alert(1)>"
        await form.locator('input[name="name"]').fill(name)
        keys=[]; committed=[]
        async def lose_first_response(route):
            if route.request.method!="POST":
                await route.continue_();return
            keys.append(route.request.headers["idempotency-key"])
            assert json.loads(route.request.post_data)=={"name":name}
            if len(keys)==1:
                response=await route.fetch()
                assert response.status==201
                committed.append(await response.json())
                await route.abort("failed")
            else:
                await route.continue_()
        await page.route("**/api/jobs/v1/studies",lose_first_response)
        await form.evaluate("form => {form.dispatchEvent(new Event('submit', {bubbles:true,cancelable:true})); form.dispatchEvent(new Event('submit', {bubbles:true,cancelable:true}));}")
        await page.locator("#create-study-error").wait_for(state="visible")
        assert len(keys)==1
        await expect(form.locator('input[name="name"]')).to_have_value(name)
        await page.locator("#submit-study").click()
        await page.wait_for_url("**/#study/"+committed[0]["id"])
        await page.locator("#study-settings-form").wait_for(state="visible")
        assert keys==[keys[0],keys[0]]
        await expect(page.locator("#page-title")).to_have_text(name)
        await expect(page.locator("#breadcrumb-title")).to_have_text(name)
        assert await page.locator("#page-title img, #breadcrumb-title img, #studies-panel img").count()==0
        await page.unroute("**/api/jobs/v1/studies",lose_first_response)
        await page.get_by_role("link",name="Studies",exact=True).click()
        await page.locator("#create-study-button").click()
        await form.locator('input[name="name"]').fill("Draft before revoke")
        await page.request.post(origin+"/_fixture/study-creator/disable")
        await expect(page.locator("#refresh-button")).to_be_enabled()
        await page.evaluate("document.getElementById('refresh-button').click()")
        await expect(page.locator("#create-study-dialog")).not_to_be_visible()
        await expect(page.locator("#create-study-button")).to_be_hidden()
        assert await form.locator('input[name="name"]').input_value()==""
        session=await (await page.request.get(origin+"/auth/session")).json()
        assert session["can_create_study"] is False
        denied=await page.request.post(origin+"/api/jobs/v1/studies",data={"name":"Revoked"},headers={"Origin":origin,"X-CSRF-Token":session["csrf_token"],"Idempotency-Key":"browser-revoked"})
        assert denied.status==403
        await page.request.post(origin+"/_fixture/study-creator/enable")
        await page.locator("#refresh-button").click()
        await expect(page.locator("#create-study-button")).to_be_visible()
        await page.locator("#create-study-button").click()
        await form.locator('input[name="name"]').fill("Other account draft")
        await creator.clear_cookies(); await creator.add_cookies(await regular.cookies())
        await expect(page.locator("#refresh-button")).to_be_enabled()
        await page.evaluate("document.getElementById('refresh-button').click()")
        await page.locator("#login-panel").wait_for(state="visible")
        await expect(page.locator("#create-study-dialog")).not_to_be_visible()
        assert await form.locator('input[name="name"]').input_value()==""
        assert not errors,errors
        await browser.close()
    print("creator_browser_passed: authorization, safe retry, duplicate suppression, plain text, revoke, account switch")

asyncio.run(main())
`
