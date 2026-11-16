package httpapi

import (
	"context"
	"strings"
	"testing"
	"time"
)

func setWebStudyCreator(t *testing.T, f *webFixture, principal string, enabled bool) {
	t.Helper()
	now := time.Now().UTC()
	_, err := f.db.Exec(context.Background(), "INSERT INTO jm_study_creators (principal_id,enabled,created_at,updated_at) VALUES (?,?,?,?) ON CONFLICT (principal_id) DO UPDATE SET enabled=excluded.enabled,updated_at=excluded.updated_at", principal, enabled, now, now)
	if err != nil {
		t.Fatal(err)
	}
}

func TestStudyCreatorHTTPAuthorizationAndSafeDefaults(t *testing.T) {
	f, admin, ordinary := studyWebFixture(t)
	path := Prefix + "/studies"
	body := map[string]any{"name": "Creator study"}
	session := func(c webCredential) map[string]any {
		return webJSON(t, f.request("GET", "/auth/session", nil, &c, nil), 200)
	}
	if session(admin)["can_create_study"] != false {
		t.Fatal("project administrator received global creation")
	}
	webError(t, f.request("POST", path, body, &admin, f.mutation(admin, "admin-denied", 0)), 403, "study_creator_required")
	setWebStudyCreator(t, f, webID("carol"), true)
	if session(ordinary)["can_create_study"] != true {
		t.Fatal("grant not visible in existing session")
	}
	webError(t, f.request("POST", path, body, &ordinary, nil), 403, "csrf_invalid")
	bad := f.mutation(ordinary, "origin", 0)
	bad["Origin"] = "https://foreign.example.test"
	webError(t, f.request("POST", path, body, &ordinary, bad), 403, "csrf_origin_invalid")
	noKey := f.mutation(ordinary, "unused", 0)
	delete(noKey, "Idempotency-Key")
	webError(t, f.request("POST", path, body, &ordinary, noKey), 400, "idempotency_key_required")
	for _, value := range []any{"", " ", strings.Repeat("a", 201), "two\nlines", 4, nil} {
		webError(t, f.request("POST", path, map[string]any{"name": value}, &ordinary, f.mutation(ordinary, "invalid-name", 0)), 422, "invalid_study_fields")
	}
	for _, field := range []string{"quotas", "project_id", "registration_open", "role"} {
		webError(t, f.request("POST", path, map[string]any{"name": "Forged", field: true}, &ordinary, f.mutation(ordinary, "forged", 0)), 422, "invalid_request")
	}
	response := f.request("POST", path, body, &ordinary, f.mutation(ordinary, "create-retry", 0))
	if response.Header.Get("ETag") != `"1"` {
		t.Fatal("missing initial study version", response.Header)
	}
	created := webJSON(t, response, 201)
	id := created["id"].(string)
	if created["registration_open"] != false || created["registration_enabled"] != true || created["can_manage"] != true {
		t.Fatal(created)
	}
	again := webJSON(t, f.request("POST", path, body, &ordinary, f.mutation(ordinary, "create-retry", 0)), 201)
	if again["id"] != id {
		t.Fatal("retry duplicated study", created, again)
	}
	webError(t, f.request("POST", path, map[string]any{"name": "Changed"}, &ordinary, f.mutation(ordinary, "create-retry", 0)), 409, "idempotency_conflict")
	studyDenied(t, f.request("GET", path+"/research", nil, &ordinary, nil))
	studyDenied(t, f.request("PUT", path+"/research/settings", map[string]any{"description": "Foreign override", "registration_open": true}, &ordinary, f.mutation(ordinary, "foreign-settings", 1)))
	studyDenied(t, f.request("GET", Prefix+"/pools", nil, &ordinary, nil))
	studyDenied(t, f.request("GET", path+"/"+id, nil, &admin, nil))
	row, err := f.db.One(context.Background(), "SELECT * FROM jm_projects WHERE id=?", id)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"quota_cpu_millicores", "quota_memory_bytes", "quota_disk_bytes", "quota_gpus", "max_active_jobs", "retained_bytes"} {
		if row[field] != int64(0) {
			t.Fatalf("nonzero %s: %#v", field, row[field])
		}
	}
	setWebStudyCreator(t, f, webID("carol"), false)
	if session(ordinary)["can_create_study"] != false {
		t.Fatal("revocation not reflected in existing session")
	}
	webError(t, f.request("POST", path, body, &ordinary, f.mutation(ordinary, "create-retry", 0)), 403, "study_creator_required")
	webJSON(t, f.request("GET", path+"/"+id, nil, &ordinary, nil), 200)
	webJSON(t, f.request("PUT", path+"/"+id+"/settings", map[string]any{"description": "Owned study", "registration_open": true}, &ordinary, f.mutation(ordinary, "open-owned", 1)), 200)
}
