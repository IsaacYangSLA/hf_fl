package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/httpapi"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
	dashboard "github.com/IsaacYangSLA/hf_fl/packages/jobs/src/hf2l_jobs/static"
)

func cleanEnvironment(t *testing.T) {
	t.Helper()
	for _, entry := range os.Environ() {
		key := strings.SplitN(entry, "=", 2)[0]
		if strings.HasPrefix(key, "JOBS_") || strings.HasPrefix(key, "HF2L_JOBS_") {
			t.Setenv(key, "")
		}
	}
}
func configureEnvironment(t *testing.T) string {
	t.Helper()
	// Clear inherited deployment configuration only inside the test process.
	keys := []string{"OPERATIONAL_CONFIG_FILE", "CONFIG", "WORKLOAD_ISSUER", "OIDC_CLIENT_SECRET_FILE", "OIDC_PUBLIC_KEY_FILE", "CURSOR_SECRET_FILE", "SESSION_SECRET_FILE", "OIDC_JWKS_URL", "OIDC_INTROSPECTION_URL", "OIDC_ENDPOINT_ORIGINS", "PLATFORM_OPERATOR_IDS"}
	for _, name := range keys {
		t.Setenv("JOBS_"+name, "")
		t.Setenv("HF2L_JOBS_"+name, "")
	}
	database := "sqlite:///" + filepath.Join(t.TempDir(), "jobs.sqlite")
	values := map[string]string{"DATABASE_URL": database, "CURSOR_SECRET": strings.Repeat("c", 32), "SESSION_SECRET": strings.Repeat("s", 32), "ALLOW_LOCAL_HTTP": "true", "OIDC_ISSUER": "https://identity.example/realms/test", "OIDC_CLIENT_ID": "dashboard", "OIDC_REDIRECT_URI": "https://manager.example/auth/callback", "AUDIENCE": "hf2l-jobs"}
	for name, value := range values {
		t.Setenv("JOBS_"+name, value)
		t.Setenv("HF2L_JOBS_"+name, value)
	}
	return database
}
func callCLI(t *testing.T, args ...string) map[string]any {
	t.Helper()
	var out, errs bytes.Buffer
	status := Run(context.Background(), args, &out, &errs)
	if status != 0 {
		t.Fatalf("command %v failed status%d stdout%s stderr%s", args, status, out.String(), errs.String())
	}
	result := map[string]any{}
	d := json.NewDecoder(&out)
	d.UseNumber()
	if e := d.Decode(&result); e != nil {
		t.Fatal(e, out.String())
	}
	return result
}
func TestCLICreatesMigratesAndAdministersRealDatabase(t *testing.T) {
	database := configureEnvironment(t)
	result := callCLI(t, "init-db")
	if result["schema_revision"] != "0003_administrative_audit" || result["status"] != "ok" {
		t.Fatal(result)
	}
	quota := filepath.Join(t.TempDir(), "quota.json")
	if e := os.WriteFile(quota, []byte(`{"cpu_millicores":4000,"memory_bytes":8589934592,"disk_bytes":17179869184,"max_running_jobs":2}`), 0600); e != nil {
		t.Fatal(e)
	}
	callCLI(t, "admin", "project-create", "--id", "example", "--name", "Example project", "--quota-file", quota)
	callCLI(t, "admin", "project-member", "--project", "example", "--principal", "user-a", "--role", "submitter")
	callCLI(t, "admin", "project-update", "--id", "example", "--retention-days", "7")
	callCLI(t, "migrate-db")
	db, e := store.Open(context.Background(), database)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	row, e := db.One(context.Background(), "SELECT * FROM jm_projects WHERE id = ?", "example")
	if e != nil || row["name"] != "Example project" || intValue(row["retention_days"]) != 7 {
		t.Fatal(row, e)
	}
	member, e := db.One(context.Background(), "SELECT * FROM jm_project_members WHERE project_id = ? AND principal_id = ?", "example", "user-a")
	if e != nil || member["role"] != "submitter" {
		t.Fatal(member, e)
	}
	rows, e := db.All(context.Background(), "SELECT * FROM jm_admin_audit WHERE resource_id = ?", "example")
	if e != nil || len(rows) < 2 {
		t.Fatal(len(rows), e)
	}
}
func TestCLIRejectsUnsafeConfigurationWithoutEchoingSecrets(t *testing.T) {
	configureEnvironment(t)
	p := filepath.Join(t.TempDir(), "bad.json")
	const secret = "example-private-value-never-display"
	if e := os.WriteFile(p, []byte(`{"unknown":{"token":"`+secret+`"}}`), 0600); e != nil {
		t.Fatal(e)
	}
	var out, errs bytes.Buffer
	status := Run(context.Background(), []string{"serve", "--config", p}, &out, &errs)
	if status != 1 || strings.Contains(errs.String(), secret) || strings.Contains(errs.String(), p) || out.Len() != 0 {
		t.Fatal(status, out.String(), errs.String())
	}
	var envelope map[string]any
	if e := json.Unmarshal(errs.Bytes(), &envelope); e != nil || envelope["error"] != "invalid_deployment_configuration" {
		t.Fatal(envelope, e)
	}
}
func TestActualGoDashboardServerAndGracefulStop(t *testing.T) {
	configureEnvironment(t)
	callCLI(t, "init-db")
	settings, e := config.Load("", "server")
	if e != nil {
		t.Fatal(e)
	}
	services, e := BuildServices(context.Background(), settings, false)
	if e != nil {
		t.Fatal(e)
	}
	defer services.Close()
	options := httpapi.Options{PublicOnly: true, AllowLocalHTTP: true, CursorSecret: []byte(settings.CursorSecret), Dashboard: dashboard.Files, Readiness: services.Ready}
	h, e := httpapi.New(services.Manager, services.Auth, options)
	if e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := newHTTPServer(listener.Addr().String(), h)
	done := make(chan error, 1)
	go func() { done <- serve(ctx, server, listener, time.Second) }()
	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	origin := "http://" + listener.Addr().String()
	for path, contains := range map[string]string{"/dashboard/": "Job manager", "/dashboard/app.js": "HF²L dashboard", "/healthz": "ok", "/readyz": "ready"} {
		response, e := client.Get(origin + path)
		if e != nil {
			t.Fatal(e)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != 200 || !strings.Contains(string(body), contains) {
			t.Fatalf("%s status%d body%s", path, response.StatusCode, body)
		}
	}
	cancel()
	select {
	case e = <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down")
	}
}
func TestShutdownCancelsStreamsAfterGraceDeadline(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	requestStopped := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(requestStopped)
	})
	server := newHTTPServer(listener.Addr().String(), handler)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, server, listener, 30*time.Millisecond) }()
	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	response, e := client.Get("http://" + listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("graceful deadline did not force-close stream")
	}
	select {
	case <-requestStopped:
	case <-time.After(time.Second):
		t.Fatal("request context not cancelled")
	}
}

func TestPrivateCallbackCompositionPersistsLogsWithoutDispatcher(t *testing.T) {
	configureEnvironment(t)
	callCLI(t, "init-db")
	settings, e := config.Load("", "server")
	if e != nil {
		t.Fatal(e)
	}
	services, e := BuildServices(context.Background(), settings, false)
	if e != nil {
		t.Fatal(e)
	}
	defer services.Close()
	if services.LocalNode != nil || services.Controller.Executor != nil {
		t.Fatal("callback listener started execution infrastructure")
	}
	ctx := context.Background()
	raw := []byte(`{"project_id":"test-project","name":"Callback job","source_id":"approved","source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","runtime_image":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","plugin":"lenet","components":[{"component_id":"owner","role":"owner","resources":{"pool_id":"cpu","cpu_millicores":1,"memory_bytes":1,"disk_bytes":1}}],"target_round":2,"max_duration_seconds":3600}`)
	spec, e := domain.DecodeJobSpec(raw)
	if e != nil {
		t.Fatal(e)
	}
	digest, e := spec.Digest()
	if e != nil {
		t.Fatal(e)
	}
	e = services.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		entries := []struct {
			table  string
			values map[string]any
		}{
			{"jm_projects", map[string]any{"id": "test-project", "name": "Project"}},
			{"jm_jobs", map[string]any{"id": "job", "project_id": "test-project", "creator_id": "owner", "name": "Callback job", "spec_json": spec.Map(), "spec_hash": digest, "state": "RUNNING", "epoch": int64(1), "current_attempt": int64(1), "target_round": int64(2), "deadline_at": time.Now().Add(time.Hour)}},
			{"jm_attempts", map[string]any{"id": "attempt", "job_id": "job", "number": int64(1), "epoch": int64(1), "state": "RUNNING"}},
			{"jm_pools", map[string]any{"id": "cpu", "name": "CPU", "node_id": "node"}},
			{"jm_allocations", map[string]any{"id": "allocation", "job_id": "job", "attempt_id": "attempt", "component_id": "owner", "pool_id": "cpu", "cpu_millicores": int64(1), "memory_bytes": int64(1), "disk_bytes": int64(1), "epoch": int64(1), "state": "RUNNING", "acknowledged": true}},
		}
		for _, entry := range entries {
			if e := tx.Insert(ctx, entry.table, entry.values); e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	options := httpapi.Options{}
	if e = ConfigureNodeAPI(&options, services); e != nil {
		t.Fatal(e)
	}
	if options.NodeCommand == nil {
		t.Fatal("private callback was not composed")
	}
	id := executor.ExecutionIdentity{JobID: "job", AttemptID: "attempt", ComponentID: "owner", Epoch: 1}
	accepted, e := options.NodeCommand(ctx, "logs", id, map[string]any{"entries": []any{"Round 1 started", "Round 1 complete"}})
	if e != nil || !accepted {
		t.Fatal(accepted, e)
	}
	rows, e := services.DB.All(ctx, "SELECT * FROM jm_log_chunks WHERE job_id = ?", "job")
	if e != nil || len(rows) != 1 || rows[0]["data"] != "Round 1 started\nRound 1 complete" {
		t.Fatal(rows, e)
	}
	project, e := services.DB.One(ctx, "SELECT * FROM jm_projects WHERE id = ?", "test-project")
	if e != nil || intValue(project["retained_bytes"]) != int64(len("Round 1 started\nRound 1 complete")) {
		t.Fatal(project, e)
	}
	id.Epoch = 2
	accepted, e = options.NodeCommand(ctx, "logs", id, map[string]any{"entries": []any{"stale"}})
	if e != nil || accepted {
		t.Fatal("stale callback was accepted", accepted, e)
	}
	rows, e = services.DB.All(ctx, "SELECT * FROM jm_log_chunks WHERE job_id = ?", "job")
	if e != nil || len(rows) != 1 {
		t.Fatal("stale callback wrote data", rows, e)
	}
}
