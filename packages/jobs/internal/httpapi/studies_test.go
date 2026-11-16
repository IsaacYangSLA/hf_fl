package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func studyWebFixture(t *testing.T) (*webFixture, webCredential, webCredential) {
	t.Helper()
	f := newWebFixture(t, nil, nil)
	f.update("jm_project_members", map[string]any{"project_id": "research", "principal_id": webID("alice")}, map[string]any{"role": "admin"})
	return f, f.login("alice"), f.login("carol")
}
func studySettings(t *testing.T, f *webFixture, admin webCredential, open bool, version int64, key string) map[string]any {
	t.Helper()
	return webJSON(t, f.request("PUT", Prefix+"/studies/research/settings", map[string]any{"description": "A participant-controlled study", "registration_open": open}, &admin, f.mutation(admin, key, version)), 200)
}
func studyDenied(t *testing.T, response *http.Response) {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode != 403 && response.StatusCode != 404 {
		t.Fatalf("authorization returned %d, want403or404", response.StatusCode)
	}
}

func TestStudyHTTPRequiresSelfApplicationAndProjectAdminApproval(t *testing.T) {
	f, admin, applicant := studyWebFixture(t)
	base := Prefix + "/studies/research"
	webError(t, f.request("GET", Prefix+"/studies", nil, nil, nil), 401, "authentication_required")
	hidden := webJSON(t, f.request("GET", Prefix+"/studies", nil, &applicant, nil), 200)
	if len(hidden["items"].([]any)) != 0 {
		t.Fatal("private project advertised before enrollment enabled", hidden)
	}
	webJSON(t, f.request("GET", base, nil, &applicant, nil), 404)
	virtual := webJSON(t, f.request("GET", base, nil, &admin, nil), 200)
	if virtual["registration_enabled"] != false || virtual["can_manage"] != true {
		t.Fatal(virtual)
	}
	settings := studySettings(t, f, admin, true, webVersion(virtual), "open")
	if settings["registration_enabled"] != true || settings["registration_open"] != true {
		t.Fatal(settings)
	}
	studyDenied(t, f.request("PUT", base+"/settings", map[string]any{"description": "Applicant override", "registration_open": false}, &applicant, f.mutation(applicant, "settings-denied", webVersion(settings))))
	visible := webJSON(t, f.request("GET", Prefix+"/studies", nil, &applicant, nil), 200)
	if len(visible["items"].([]any)) != 1 {
		t.Fatal(visible)
	}
	body := map[string]any{"participant_id": "carol", "message": "I would like to contribute local data."}
	forged := map[string]any{"participant_id": "carol", "principal_id": webID("bob")}
	webError(t, f.request("POST", base+"/applications", forged, &applicant, f.mutation(applicant, "forged", 0)), 422, "invalid_request")
	webError(t, f.request("POST", base+"/applications", body, &applicant, nil), 403, "csrf_invalid")
	noKey := f.mutation(applicant, "removed", 0)
	delete(noKey, "Idempotency-Key")
	webError(t, f.request("POST", base+"/applications", body, &applicant, noKey), 400, "idempotency_key_required")
	appResponse := f.request("POST", base+"/applications", body, &applicant, f.mutation(applicant, "apply", 0))
	app := webJSON(t, appResponse, 202)
	if app["principal_id"] != webID("carol") || app["participant_id"] != "carol" || app["status"] != "pending" {
		t.Fatal(app)
	}
	if appResponse.Header.Get("ETag") == "" || appResponse.Header.Get("Location") != base+"/application" {
		t.Fatal("missing enrollment response headers", appResponse.Header)
	}
	replay := webJSON(t, f.request("POST", base+"/applications", body, &applicant, f.mutation(applicant, "apply", 0)), 202)
	if replay["id"] != app["id"] {
		t.Fatal("repeated application created another identity", replay)
	}
	own := webJSON(t, f.request("GET", base+"/application", nil, &applicant, nil), 200)
	if own["application"].(map[string]any)["id"] != app["id"] {
		t.Fatal(own)
	}
	studyDenied(t, f.request("GET", base+"/applications", nil, &applicant, nil))
	other := f.login("bob")
	otherRequest := webJSON(t, f.request("GET", base+"/application", nil, &other, nil), 200)
	if otherRequest["application"] != nil {
		t.Fatal("another applicant's request leaked", otherRequest)
	}
	studyDenied(t, f.request("GET", base+"/applications", nil, &other, nil))
	review := base + "/applications/" + app["id"].(string)
	studyDenied(t, f.request("POST", review+"/approve", map[string]any{}, &applicant, f.mutation(applicant, "self-approve", webVersion(app))))
	webError(t, f.request("POST", review+"/approve", map[string]any{}, &admin, f.mutation(admin, "missing-version", 0)), 428, "if_match_required")
	approved := webJSON(t, f.request("POST", review+"/approve", map[string]any{"reason": "Participation reviewed"}, &admin, f.mutation(admin, "approve", webVersion(app))), 200)
	if approved["status"] != "approved" || approved["reviewer_id"] != webID("alice") || webVersion(approved) <= webVersion(app) {
		t.Fatal(approved)
	}
	// Study approval does not convert an applicant into a job submitter.
	webError(t, f.request("POST", Prefix+"/jobs", webSpec("Unauthorized creation"), &applicant, f.mutation(applicant, "create-denied", 0)), 403, "project_submitter_required")
	row, e := f.db.One(context.Background(), "SELECT COUNT(*) AS n FROM jm_project_members WHERE project_id=? AND principal_id=?", "research", webID("carol"))
	if e != nil || row["n"] != int64(0) {
		t.Fatal("approval granted project authority", row, e)
	}
	webJSON(t, f.request("POST", review+"/withdraw", map[string]any{}, &applicant, f.mutation(applicant, "withdraw-approved", webVersion(approved))), 409)
	webJSON(t, f.request("POST", review+"/reject", map[string]any{}, &admin, f.mutation(admin, "reject-approved", webVersion(approved))), 409)
	webJSON(t, f.request("POST", review+"/revoke", map[string]any{}, &admin, f.mutation(admin, "no-revoke", webVersion(approved))), 404)
}

func TestStudyHTTPValidatesBodiesMethodsAndSessionOrigin(t *testing.T) {
	f, admin, applicant := studyWebFixture(t)
	base := Prefix + "/studies/research"
	for i, body := range []map[string]any{
		{"description": "missing open"},
		{"registration_open": true},
		{"registration_open": "true", "description": "wrong type"},
		{"registration_open": true, "description": nil},
		{"registration_open": true, "description": "Unknown field", "enabled": false},
	} {
		webError(t, f.request("PUT", base+"/settings", body, &admin, f.mutation(admin, fmt.Sprintf("bad-%d", i), 1)), 422, "invalid_request")
	}
	good := map[string]any{"registration_open": true, "description": "Public study"}
	bad := f.mutation(admin, "wrong-origin", 1)
	bad["Origin"] = "https://foreign.example.test"
	webError(t, f.request("PUT", base+"/settings", good, &admin, bad), 403, "csrf_origin_invalid")
	webError(t, f.request("DELETE", base+"/settings", nil, &admin, nil), 405, "http_error")
	for _, path := range []string{Prefix + "/studies?limit=0", Prefix + "/studies?limit=101", Prefix + "/studies?cursor=" + strings.Repeat("x", 4097)} {
		webError(t, f.request("GET", path, nil, &admin, nil), 422, "invalid_request")
	}
	studySettings(t, f, admin, true, 1, "open")
	for i, body := range []map[string]any{
		{"participant_id": nil},
		{"participant_id": "carol", "message": true},
		{"participant_id": "carol", "status": "approved"},
	} {
		webError(t, f.request("POST", base+"/applications", body, &applicant, f.mutation(applicant, fmt.Sprintf("bad-app-%d", i), 0)), 422, "invalid_request")
	}
	app := webJSON(t, f.request("POST", base+"/applications", map[string]any{"participant_id": "carol"}, &applicant, f.mutation(applicant, "apply", 0)), 202)
	path := base + "/applications/" + app["id"].(string) + "/withdraw"
	webError(t, f.request("POST", path, map[string]any{"reason": "not an accepted field"}, &applicant, f.mutation(applicant, "extra-withdraw", webVersion(app))), 422, "invalid_request")
	webError(t, f.raw("POST", base+"/applications", []byte(`{"participant_id":"carol","participant_id":"bob"}`), &applicant, f.mutation(applicant, "duplicate", 0)), 422, "invalid_request")
}

func TestStudyHTTPClosingRegistrationKeepsOwnRequestAndAllowsWithdrawal(t *testing.T) {
	f, admin, applicant := studyWebFixture(t)
	base := Prefix + "/studies/research"
	settings := studySettings(t, f, admin, true, 1, "open")
	app := webJSON(t, f.request("POST", base+"/applications", map[string]any{"participant_id": "carol"}, &applicant, f.mutation(applicant, "apply", 0)), 202)
	closed := studySettings(t, f, admin, false, webVersion(settings), "close")
	if closed["registration_enabled"] != true || closed["registration_open"] != false {
		t.Fatal("closing disabled required approval", closed)
	}
	own := webJSON(t, f.request("GET", base, nil, &applicant, nil), 200)
	if own["my_application"].(map[string]any)["id"] != app["id"] {
		t.Fatal(own)
	}
	appPath := base + "/applications/" + app["id"].(string)
	withdrawn := webJSON(t, f.request("POST", appPath+"/withdraw", map[string]any{}, &applicant, f.mutation(applicant, "withdraw", webVersion(app))), 200)
	if withdrawn["status"] != "withdrawn" {
		t.Fatal(withdrawn)
	}
	webJSON(t, f.request("POST", base+"/applications", map[string]any{"participant_id": "carol"}, &applicant, f.mutation(applicant, "closed-reapply", 0)), 409)
	studySettings(t, f, admin, true, webVersion(closed), "reopen")
	again := webJSON(t, f.request("POST", base+"/applications", map[string]any{"participant_id": "carol"}, &applicant, f.mutation(applicant, "new-application", 0)), 202)
	if again["status"] != "pending" || again["id"] != app["id"] {
		t.Fatal("reapplication lost durable applicant identity", again)
	}
}
