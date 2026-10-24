// Package lifecycle qualifies the complete native Go manager against real services.
package lifecycle

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/app"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/auth"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/exchange"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/httpapi"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/manager"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
	dashboard "github.com/IsaacYangSLA/hf_fl/packages/jobs/src/hf2l_jobs/static"
	"github.com/golang-jwt/jwt/v5"
)

type object = map[string]any
type testConfig struct {
	Root           string `json:"root"`
	OwnedRoot      string `json:"owned_root"`
	Profile        string `json:"profile"`
	Image          string `json:"image"`
	Python         string `json:"python"`
	DatabaseConfig string `json:"database_config"`
	StorageConfig  string `json:"storage_config"`
}

func text(v any) string { s, _ := v.(string); return s }
func integer(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	case float64:
		return int64(n)
	}
	return 0
}
func obj(v any) object  { m, _ := v.(map[string]any); return m }
func items(v any) []any { a, _ := v.([]any); return a }
func readPrivate(path string) (object, error) {
	st, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || sys.Uid != uint32(os.Getuid()) || sys.Nlink != 1 || st.Size() > 1<<20 {
		return nil, errors.New("private regular configuration required")
	}
	data, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	v, e := domain.DecodeJSON(data)
	if e != nil {
		return nil, e
	}
	result, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("configuration object required")
	}
	return result, nil
}
func privateJSON(path string, v any) error {
	data, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, append(data, 10), 0600)
}
func contents(t *testing.T, path string) string {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}
func freePort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
func waitFile(ctx context.Context, path string) error {
	for {
		if _, e := os.Stat(path); e == nil {
			return nil
		}
		if _, e := os.Stat(filepath.Join(filepath.Dir(path), "failure.json")); e == nil {
			return errors.New("independent Exchange fixture failed; inspect private receipt")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

type apiClient struct {
	client   *http.Client
	endpoint string
	key      *rsa.PrivateKey
	issuer   string
}

func (a *apiClient) token(subject string) string {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": a.issuer, "sub": subject, "aud": "hf2l-jobs", "iat": now.Add(-time.Second).Unix(), "exp": now.Add(5 * time.Minute).Unix(), "scope": "jobs"})
	token.Header["typ"] = "at+jwt"
	raw, e := token.SignedString(a.key)
	if e != nil {
		panic(e)
	}
	return raw
}
func (a *apiClient) request(ctx context.Context, method, path string, body any, version int64) (object, int, error) {
	var input io.Reader
	if body != nil {
		data, e := json.Marshal(body)
		if e != nil {
			return nil, 0, e
		}
		input = bytes.NewReader(data)
	}
	r, e := http.NewRequestWithContext(ctx, method, a.endpoint+path, input)
	if e != nil {
		return nil, 0, e
	}
	r.Header.Set("Authorization", "Bearer "+a.token("owner"))
	r.Header.Set("Accept", "application/json")
	if method != "GET" {
		r.Header.Set("Idempotency-Key", domain.NewID())
	}
	if version > 0 {
		r.Header.Set("If-Match", fmt.Sprintf("%q", strconv.FormatInt(version, 10)))
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	response, e := a.client.Do(r)
	if e != nil {
		return nil, 0, e
	}
	defer response.Body.Close()
	data, e := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if e != nil {
		return nil, response.StatusCode, e
	}
	decoded, e := domain.DecodeJSON(data)
	if e != nil {
		return nil, response.StatusCode, e
	}
	return obj(decoded), response.StatusCode, nil
}
func (a *apiClient) get(ctx context.Context, id string) (object, error) {
	job, status, e := a.request(ctx, "GET", "/api/jobs/v1/jobs/"+id, nil, 0)
	if e != nil {
		return nil, e
	}
	if status != 200 {
		return nil, fmt.Errorf("job lookup status %d", status)
	}
	return job, nil
}
func startIssuer(t *testing.T) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(object{"issuer": server.URL, "authorization_endpoint": server.URL + "/authorize", "token_endpoint": server.URL + "/token", "jwks_uri": server.URL + "/jwks", "introspection_endpoint": server.URL + "/introspect", "code_challenge_methods_supported": []string{"S256"}, "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/introspect":
			r.ParseForm()
			token, e := jwt.Parse(r.Form.Get("token"), func(token *jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(server.URL), jwt.WithAudience("hf2l-jobs"))
			if e != nil || !token.Valid {
				json.NewEncoder(w).Encode(object{"active": false})
				return
			}
			claims := token.Claims.(jwt.MapClaims)
			json.NewEncoder(w).Encode(object{"active": true, "sub": claims["sub"], "iss": server.URL, "aud": "hf2l-jobs", "client_id": "dashboard", "exp": claims["exp"]})
		default:
			http.NotFound(w, r)
		}
	}))
	return server, key
}
func publicKeyPEM(key *rsa.PrivateKey) string {
	raw, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if e != nil {
		panic(e)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: raw}))
}
func settings(t *testing.T, c testConfig, ready object, dbURL, issuer, pub string, edgePort, gatewayPort int) config.Settings {
	t.Helper()
	root := filepath.Join(c.Root, "managed")
	if e := os.MkdirAll(root, 0700); e != nil {
		t.Fatal(e)
	}
	file := func(k string) string { return text(ready[k]) }
	storage := obj(ready["storage"])
	storage["capacity_bytes"] = int64(2 << 30)
	datasets := obj(ready["datasets"])
	extra := object{
		"executor":    object{"root": c.OwnedRoot, "profile_path": c.Profile},
		"node":        object{"node_id": "lifecycle-node", "pool_id": "cpu", "ledger_path": filepath.Join(c.Root, "node-ledger.json"), "capacity": object{"cpu_millicores": int64(2000), "memory_bytes": int64(2 << 30), "disk_bytes": int64(16 << 30), "pids": int64(128), "io_bps": int64(16 << 20)}, "dataset_bindings": object{"alice-data": object{"kind": "npz", "host_path": text(datasets["alice"]), "project_id": "lifecycle", "participant_id": "alice"}, "bob-data": object{"kind": "npz", "host_path": text(datasets["bob"]), "project_id": "lifecycle", "participant_id": "bob"}}},
		"provisioner": object{"root": root, "socket_root": c.OwnedRoot, "exchange_endpoint": file("ordinary_endpoint"), "admin_token_file": file("admin_token_file"), "client_ca_certificate": file("client_ca_file"), "client_ca_key": file("client_ca_key_file"), "managed_exchange_endpoint": fmt.Sprintf("https://127.0.0.1:%d", edgePort), "gateway_endpoint": fmt.Sprintf("https://127.0.0.1:%d", gatewayPort), "service_ca_file": file("service_ca_file"), "exchange_ca_file": file("service_ca_file"), "storage_pool_id": "sources", "exchange_storage_pool_id": "objects", "exchange_storage": storage},
		"gateway":     object{"host": "127.0.0.1", "port": int64(gatewayPort), "tls_certificate": file("server_certificate"), "tls_key": file("server_key"), "client_ca_file": file("client_ca_file"), "backend_endpoint": file("gateway_backend_endpoint"), "backend_secret_file": file("backend_secret_file"), "ca_file": file("service_ca_file"), "backend_client_certificate": file("backend_client_certificate"), "backend_client_key": file("backend_client_key"), "origin_endpoints": []string{text(storage["endpoint"])}, "allow_local_origin_http": strings.HasPrefix(text(storage["endpoint"]), "http://")},
		"boundaries":  object{"exchange": object{"host": "127.0.0.1", "port": int64(edgePort), "tls_certificate": file("server_certificate"), "tls_key": file("server_key"), "client_ca_file": file("client_ca_file"), "backend_endpoint": file("managed_backend_endpoint"), "backend_secret_file": file("backend_secret_file"), "ca_file": file("service_ca_file"), "backend_client_certificate": file("backend_client_certificate"), "backend_client_key": file("backend_client_key")}},
	}
	return config.Settings{DatabaseURL: dbURL, CursorSecret: strings.Repeat("c", 32), SessionSecret: strings.Repeat("s", 32), OIDC: config.OIDCSettings{Issuer: issuer, ClientID: "dashboard", RedirectURI: "https://localhost/auth/callback", Audience: "hf2l-jobs", PublicKey: pub, TimeoutSeconds: 5, JWKSCacheSeconds: 300, AllowLocalHTTP: true}, Workload: &config.WorkloadSettings{Issuer: file("workload_issuer"), ExchangeAudience: "exchange-managed", GatewayAudience: "hf2l-transfer", NodeAudience: "hf2l-nodes", PrivateKey: contents(t, file("workload_private_key_file")), PublicKey: contents(t, file("workload_public_key_file")), KeyID: "lifecycle"}, MaxBodyBytes: 1 << 20, GracefulShutdownTimeoutSeconds: 15, Extra: extra}
}
func bootstrap(ctx context.Context, t *testing.T, s config.Settings, ready object, c testConfig, actor string) {
	t.Helper()
	db, e := store.Open(ctx, s.DatabaseURL)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	m, e := manager.New(db, []byte(s.CursorSecret))
	if e != nil {
		t.Fatal(e)
	}
	services := &app.Services{Settings: s, DB: db, Manager: m}
	if e = app.ConfigureAdminPolicy(ctx, services); e != nil {
		t.Fatal(e)
	}
	admin := func(op string, v object) {
		t.Helper()
		if _, e := m.TrustedAdmin(ctx, fmt.Sprintf("unix:%d", os.Getuid()), op, v); e != nil {
			t.Fatalf("bootstrap %s: %v", op, e)
		}
	}
	admin("project-create", object{"id": "lifecycle", "name": "Native Go lifecycle", "quota": object{"cpu_millicores": int64(6000), "memory_bytes": int64(8 << 30), "disk_bytes": int64(8 << 30), "retained_bytes": int64(8 << 30), "max_running_jobs": int64(3), "gpu_count": int64(0)}})
	admin("project-member", object{"project": "lifecycle", "principal": actor, "role": "submitter"})
	admin("storage-pool-set", object{"id": "sources", "name": "Source and logs", "node_id": "manager-lifecycle", "disk_bytes": int64(1 << 30)})
	admin("object-store-pool-set", object{"id": "objects", "name": "Versioned model objects", "disk_bytes": int64(2 << 30)})
	admin("pool-set", object{"id": "cpu", "name": "Qualified CPU execution", "node_id": "lifecycle-node", "cpu_millicores": int64(1500), "memory_bytes": int64(1536 << 20), "disk_bytes": int64(4 << 30), "sandbox_profiles": []string{"runsc-cpu-v1"}, "healthy": true})
	admin("source-approve", object{"id": "lifecycle-source", "project_id": "lifecycle", "mirror_path": text(ready["source_mirror"]), "allowed_commits": []string{text(ready["source_commit"])}, "max_bytes": int64(1 << 20), "max_files": int64(64), "max_git_bytes": int64(8 << 20), "max_git_files": int64(512)})
	admin("image-approve", object{"id": "worker", "project_id": "lifecycle", "digest": c.Image})
	for _, p := range []string{"alice", "bob"} {
		admin("dataset-approve", object{"id": p + "-data", "project_id": "lifecycle", "participant_id": p, "dataset_label": "Synthetic " + p, "node_id": "lifecycle-node"})
	}
}
func jobSpec(name string, ready object) object {
	resources := func() object {
		return object{"pool_id": "cpu", "cpu_millicores": int64(250), "memory_bytes": int64(256 << 20), "disk_bytes": int64(64 << 20), "gpu_count": int64(0), "sandbox_profile": "runsc-cpu-v1"}
	}
	return object{"project_id": "lifecycle", "name": name, "source_id": "lifecycle-source", "source_commit": text(ready["source_commit"]), "runtime_image": "worker", "plugin": "trainer", "target_round": int64(2), "max_duration_seconds": int64(600), "options": object{"delay_seconds": int64(15)}, "secret_refs": object{}, "participants": []any{object{"participant_id": "alice", "dataset_binding": "alice-data", "mode": "managed", "component_id": "alice"}, object{"participant_id": "bob", "dataset_binding": "bob-data", "mode": "managed", "component_id": "bob"}}, "components": []any{object{"component_id": "owner", "role": "owner", "resources": resources()}, object{"component_id": "alice", "role": "participant", "participant_id": "alice", "resources": resources()}, object{"component_id": "bob", "role": "participant", "participant_id": "bob", "resources": resources()}}}
}
func checkpointValue(data []byte) (float64, error) {
	if len(data) < 8 {
		return 0, errors.New("short SafeTensors")
	}
	n := binary.LittleEndian.Uint64(data[:8])
	if n > uint64(len(data)-8) {
		return 0, errors.New("invalid SafeTensors header")
	}
	header, e := domain.DecodeJSON(data[8 : 8+n])
	if e != nil {
		return 0, e
	}
	tensors := obj(header)
	count := 0
	value := 0.0
	for name, v := range tensors {
		if name == "__metadata__" {
			continue
		}
		tensor := obj(v)
		if text(tensor["dtype"]) != "F32" {
			return 0, errors.New("unexpected checkpoint dtype")
		}
		offsets := items(tensor["data_offsets"])
		if len(offsets) != 2 {
			return 0, errors.New("invalid tensor offsets")
		}
		start, end := integer(offsets[0]), integer(offsets[1])
		if start < 0 || end < start || uint64(end) > uint64(len(data))-8-n || (end-start)%4 != 0 {
			return 0, errors.New("invalid tensor bounds")
		}
		for i := start; i < end; i += 4 {
			f := float64(math.Float32frombits(binary.LittleEndian.Uint32(data[8+n+uint64(i):])))
			if count == 0 {
				value = f
			} else if math.Abs(value-f) > 1e-6 {
				return 0, errors.New("tensor values disagree")
			}
			count++
		}
	}
	if count != 6 {
		return 0, errors.New("unexpected tensor count")
	}
	return value, nil
}
func chargedInventory(rows []map[string]any) int {
	count := 0
	for _, row := range rows {
		if integer(row["disk_released"]) != 1 || integer(row["stopped"]) != 1 || integer(row["auxiliary_bytes"]) != 0 {
			count++
		}
	}
	return count
}
func physicalCleanup(ctx context.Context, t *testing.T, linux *executor.LinuxExecutor, rows []map[string]any, jobs []string) object {
	t.Helper()
	execute := func(prefix []string, args ...string) []byte {
		if len(prefix) == 0 {
			t.Fatal("qualified command prefix missing")
		}
		argv := append(append([]string{}, prefix[1:]...), args...)
		result, e := exec.CommandContext(ctx, prefix[0], argv...).Output()
		if e != nil {
			t.Fatal("independent owned-resource inventory command failed")
		}
		return result
	}
	for _, id := range jobs {
		data := execute(linux.Profile.DockerCommand, "ps", "-a", "--filter", "label=hf2l.job_id="+id, "--format", "{{.ID}}")
		if strings.TrimSpace(string(data)) != "" {
			t.Fatal("owned job container remains")
		}
	}
	mounts := string(execute(linux.Profile.SystemCommand, "findmnt", "-rn", "-o", "TARGET"))
	loops, e := domain.DecodeJSON(execute(linux.Profile.SystemCommand, "losetup", "--list", "--json", "--output", "NAME,BACK-FILE"))
	if e != nil {
		t.Fatal(e)
	}
	return verifyPhysicalCleanup(linux.Root, rows, mounts, items(obj(loops)["loopdevices"]), t)
}
func verifyPhysicalCleanup(root string, rows []map[string]any, mounts string, loops []any, reporter interface {
	Helper()
	Fatal(...any)
}) object {
	reporter.Helper()
	for _, row := range rows {
		prefix := filepath.Join(root, text(row["execution_key"]))
		if _, e := os.Lstat(filepath.Join(prefix, "state.ext4")); !os.IsNotExist(e) {
			reporter.Fatal("owned backing image remains")
		}
		for _, line := range strings.Split(mounts, "\n") {
			if line == prefix || strings.HasPrefix(line, prefix+"/") {
				reporter.Fatal("owned mounted execution remains")
			}
		}
		for _, loop := range loops {
			path := text(obj(loop)["back-file"])
			if path == prefix || strings.HasPrefix(path, prefix+"/") {
				reporter.Fatal("owned loop association remains")
			}
		}
	}
	return object{"containers": 0, "mounts": 0, "loop_devices": 0, "backing_images": 0, "retained_audit_rows": len(rows)}
}
func floatValue(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case json.Number:
		f, _ := n.Float64()
		return f
	case int64:
		return float64(n)
	}
	return 0
}
func auditLineage(ctx context.Context, t *testing.T, services *app.Services, ready object, job string) object {
	t.Helper()
	space, e := services.Provisioner.OwnedSpace(ctx, job)
	if e != nil || space == "" {
		t.Fatal("owned Exchange space missing")
	}
	client, e := exchange.New(exchange.Config{Endpoint: text(ready["ordinary_endpoint"]), TokenFile: text(ready["admin_token_file"]), CAFile: text(ready["service_ca_file"]), Timeout: 30 * time.Second, Retries: 2})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	records := []any{}
	cursor := ""
	for {
		filters := url.Values{"kind": {"model.global"}, "state": {"published"}, "limit": {"100"}}
		if cursor != "" {
			filters.Set("cursor", cursor)
		}
		page, e := client.RecordsPage(ctx, space, filters)
		if e != nil {
			t.Fatal(e)
		}
		records = append(records, items(page["items"])...)
		cursor = text(page["next_cursor"])
		if cursor == "" {
			break
		}
	}
	rounds := map[int64]object{}
	for _, raw := range records {
		record := obj(raw)
		manifest := obj(obj(record["metadata"])["hf2l_files"])["fedavg_round.json"]
		if manifest == nil {
			t.Fatal("global record has no inline round manifest")
		}
		doc := obj(manifest)
		n := integer(doc["round"])
		if rounds[n] != nil {
			t.Fatal("duplicate global round publication")
		}
		rounds[n] = object{"record_id": record["id"], "manifest": doc}
	}
	if len(rounds) != 3 || rounds[0] == nil || rounds[1] == nil || rounds[2] == nil {
		t.Fatal("expected exact initial plus two global publications")
	}
	main, e := client.GetReference(ctx, space, "main")
	if e != nil {
		t.Fatal(e)
	}
	if main["record_id"] != rounds[2]["record_id"] {
		t.Fatal("main does not select final global")
	}
	audit := []any{}
	for n := int64(1); n <= 2; n++ {
		doc := obj(rounds[n]["manifest"])
		if doc["base_revision"] != rounds[n-1]["record_id"] {
			t.Fatal("global lineage mismatch")
		}
		submissions := items(doc["submissions"])
		if len(submissions) != 2 {
			t.Fatal("wrong accepted participant count")
		}
		seen := map[string]bool{}
		for _, raw := range submissions {
			summary := obj(raw)
			participant := text(summary["participant"])
			count := int64(16)
			weight := .4
			if participant == "bob" {
				count = 24
				weight = .6
			} else if participant != "alice" {
				t.Fatal("unexpected participant")
			}
			if seen[participant] || integer(summary["num_examples"]) != count || math.Abs(floatValue(summary["coefficient"])-weight) > 1e-12 {
				t.Fatal("weighted sample attribution mismatch")
			}
			seen[participant] = true
			submitted, e := client.GetRecord(ctx, space, text(summary["resolved_revision"]))
			if e != nil {
				t.Fatal(e)
			}
			manifest := obj(obj(submitted["metadata"])["hf2l_files"])["fedavg_submission.json"]
			source := obj(manifest)
			if source["participant"] != participant || integer(source["num_examples"]) != count || integer(source["source_round"]) != n-1 || source["base_revision"] != rounds[n-1]["record_id"] {
				t.Fatal("client base/sample lineage mismatch")
			}
		}
		audit = append(audit, object{"round": n, "record_id": rounds[n]["record_id"], "base_revision": doc["base_revision"], "participants": 2, "weights": []float64{.4, .6}})
	}
	return object{"space_id": space, "global_publications": 3, "rounds": audit, "final_record_id": main["record_id"], "final_checkpoint_sha256": obj(obj(rounds[2]["manifest"])["checkpoint_files_sha256"])["model.safetensors"]}
}
func fileSHA(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func observedTraining(ctx context.Context, services *app.Services, job string) (bool, object, error) {
	row, e := services.DB.One(ctx, "SELECT * FROM jm_jobs WHERE id = ?", job)
	if e != nil {
		return false, nil, e
	}
	attempt, e := services.DB.One(ctx, "SELECT * FROM jm_attempts WHERE job_id = ? AND number = ?", job, integer(row["current_attempt"]))
	if e != nil || attempt == nil {
		return false, nil, e
	}
	for _, participant := range []string{"alice", "bob"} {
		identity := executor.ExecutionIdentity{JobID: job, AttemptID: text(attempt["id"]), ComponentID: participant, Epoch: integer(attempt["epoch"])}
		observed, e := services.Node.Inspect(ctx, identity)
		if e != nil {
			return false, nil, e
		}
		if strings.EqualFold(observed.State, "RUNNING") && observed.Phase == "training" && observed.Readiness == "training" {
			return true, object{"job_id": job, "attempt_id": identity.AttemptID, "component_id": participant, "epoch": identity.Epoch, "state": observed.State, "phase": observed.Phase, "readiness": observed.Readiness}, nil
		}
	}
	return false, nil, nil
}
func TestNativeGoFederatedLifecycle(t *testing.T) {
	cfgPath := os.Getenv("HF2L_GO_LIFECYCLE_CONFIG")
	if cfgPath == "" {
		t.Skip("set HF2L_GO_LIFECYCLE_CONFIG for owned qualified-runtime/PostgreSQL/S3 acceptance")
	}
	raw, e := readPrivate(cfgPath)
	if e != nil {
		t.Fatal(e)
	}
	data, _ := json.Marshal(raw)
	var c testConfig
	if e = json.Unmarshal(data, &c); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{c.Root, c.OwnedRoot, c.Profile, c.Python, c.DatabaseConfig, c.StorageConfig} {
		if !filepath.IsAbs(p) {
			t.Fatal("absolute owned paths required")
		}
	}
	relative, e := filepath.Rel(c.OwnedRoot, c.Root)
	if e != nil || relative == "." || strings.HasPrefix(relative, "..") {
		t.Fatal("lifecycle artifacts must be inside owned runtime root")
	}
	if e = os.Mkdir(c.Root, 0700); e != nil {
		t.Fatal("fresh lifecycle root required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	report := object{"implementation": "native Go manager/controller/scheduler/provisioner/executor/node/proxy/edge/gateway", "status": "FAIL", "scopes": []string{"actual qualified CPU execution", "real PostgreSQL", "real versioned S3", "actual managed mTLS transfers", "unchanged sandbox Python FL application"}}
	report["worker_image"] = c.Image
	if profileHash, e := fileSHA(c.Profile); e == nil {
		report["qualified_profile_sha256"] = profileHash
	} else {
		t.Fatal(e)
	}
	if binary, e := os.Executable(); e == nil {
		if hash, e := fileSHA(binary); e == nil {
			report["go_test_binary_sha256"] = hash
		} else {
			t.Fatal(e)
		}
	}
	defer func() {
		if e := privateJSON(filepath.Join(c.Root, "result.json"), report); e != nil {
			t.Log("result receipt write failed")
		}
	}()
	fixtureRoot := filepath.Join(c.Root, "exchange")
	log, e := os.OpenFile(filepath.Join(c.Root, "exchange-fixture.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	fixture := exec.Command(c.Python, "fixture.py", "--runtime", fixtureRoot, "--database-config", c.DatabaseConfig, "--storage-config", c.StorageConfig)
	fixture.Stdout = log
	fixture.Stderr = log
	fixture.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	if e = fixture.Start(); e != nil {
		t.Fatal(e)
	}
	fixtureStopped := false
	retainFixtureForRecovery := false
	defer func() {
		if retainFixtureForRecovery {
			report["exchange_fixture_retained_for_recovery"] = true
			report["exchange_fixture_pid"] = fixture.Process.Pid
			return
		}
		if !fixtureStopped {
			fixture.Process.Signal(syscall.SIGTERM)
			done := make(chan error, 1)
			go func() { done <- fixture.Wait() }()
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				fixture.Process.Kill()
				<-done
			}
		}
		if cleanup, e := readPrivate(filepath.Join(fixtureRoot, "cleanup.json")); e == nil {
			report["exchange_cleanup"] = cleanup
			if cleanup["server_stopped"] != true || cleanup["bucket_removed"] != true || cleanup["schema_removed"] != true || len(items(cleanup["errors"])) != 0 {
				report["status"] = "FAIL"
				t.Error("owned Exchange cleanup incomplete")
			}
		} else {
			report["status"] = "FAIL"
			t.Error("owned Exchange cleanup receipt missing or unreadable")
		}
	}()
	if e = waitFile(ctx, filepath.Join(fixtureRoot, "lifecycle-ready.json")); e != nil {
		t.Fatal(e)
	}
	ready, e := readPrivate(filepath.Join(fixtureRoot, "lifecycle-ready.json"))
	if e != nil {
		t.Fatal(e)
	}
	dbCfg, e := readPrivate(c.DatabaseConfig)
	if e != nil {
		t.Fatal(e)
	}
	databaseURL := text(obj(dbCfg["databases"])["lifecycle"])
	if databaseURL == "" {
		t.Fatal("dedicated lifecycle database URL required")
	}
	databaseURL = strings.Replace(databaseURL, "postgresql+psycopg://", "postgresql://", 1)
	databaseURL = strings.Replace(databaseURL, "postgres://", "postgresql://", 1)
	adminDB, e := store.Open(ctx, databaseURL)
	if e != nil {
		t.Fatal(e)
	}
	defer adminDB.Close()
	schema := "go_lifecycle_" + domain.NewID()
	if _, e = adminDB.Exec(ctx, "CREATE SCHEMA "+schema); e != nil {
		t.Fatal(e)
	}
	schemaClean := false
	defer func() {
		if schemaClean {
			_, e := adminDB.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
			report["manager_schema_removed"] = e == nil
			if e != nil {
				report["status"] = "FAIL"
				t.Error("owned manager schema cleanup failed")
			}
		} else {
			report["manager_schema_retained_for_recovery"] = schema
		}
	}()
	u, e := url.Parse(databaseURL)
	if e != nil {
		t.Fatal(e)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	databaseURL = u.String()
	issuer, key := startIssuer(t)
	defer issuer.Close()
	actor := domain.PrincipalID(issuer.URL, "owner")
	s := settings(t, c, ready, databaseURL, issuer.URL, publicKeyPEM(key), freePort(t), freePort(t))
	if e = privateJSON(filepath.Join(c.Root, "operational-settings.json"), s); e != nil {
		t.Fatal("private operational settings receipt failed")
	}
	bootstrap(ctx, t, s, ready, c, actor)
	serviceCtx, stopServices := context.WithCancel(ctx)
	serviceErrors := make(chan error, 2)
	defer func() {
		stopServices()
		for i := 0; i < 2; i++ {
			select {
			case <-serviceErrors:
			case <-time.After(15 * time.Second):
				report["status"] = "FAIL"
				t.Error("managed ingress shutdown unconfirmed")
			}
		}
	}()
	go func() { serviceErrors <- app.RunGateway(serviceCtx, s, app.Arguments{}) }()
	go func() { serviceErrors <- app.RunEdge(serviceCtx, s, app.Arguments{}) }()
	services, e := app.BuildServices(ctx, s, true)
	if e != nil {
		t.Fatalf("full Go composition: %v", e)
	}
	defer services.Close()
	provider, ok := services.Auth.Provider.(*auth.OIDCProvider)
	if !ok {
		t.Fatal("native OIDC provider missing")
	}
	provider.Client = issuer.Client()
	if e = services.LocalNode.Backend.(*executor.LinuxExecutor).QualifyHealth(ctx); e != nil {
		t.Fatal(e)
	}
	handler, e := httpapi.New(services.Manager, services.Auth, httpapi.Options{PublicOnly: true, CursorSecret: []byte(s.CursorSecret), Readiness: services.Ready, ArtifactBroker: services.ArtifactBroker, Dashboard: dashboard.Files})
	if e != nil {
		t.Fatal(e)
	}
	api := httptest.NewUnstartedServer(handler)
	api.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	pair, e := tls.LoadX509KeyPair(text(ready["server_certificate"]), text(ready["server_key"]))
	if e != nil {
		t.Fatal(e)
	}
	api.TLS.Certificates = []tls.Certificate{pair}
	api.StartTLS()
	defer api.Close()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(contents(t, text(ready["service_ca_file"])))) {
		t.Fatal("service CA")
	}
	client := &apiClient{client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, Timeout: 60 * time.Second}, endpoint: api.URL, key: key, issuer: issuer.URL}
	jobs := []string{}
	cleanupDone := false
	var passMu sync.Mutex
	pass := func(callctx context.Context) error {
		passMu.Lock()
		defer passMu.Unlock()
		_, e := app.ControllerPass(callctx, services)
		return e
	}
	defer func() {
		if cleanupDone {
			return
		}
		// Keep the independent authority alive until failed-job cleanup is proven.
		// A timed-out recovery must not erase its bucket/schema while retaining only
		// the manager ledger; exact private settings permit a later native retry.
		retainFixtureForRecovery = true
		recoveryCtx, recoveryCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer recoveryCancel()
		for _, id := range jobs {
			job, e := services.Manager.GetJob(recoveryCtx, actor, id)
			if e == nil && !domain.IsTerminal(text(job["state"])) {
				services.Manager.Cancel(recoveryCtx, actor, id, integer(job["version"]), domain.NewID())
			}
		}
		for recoveryCtx.Err() == nil {
			_ = pass(recoveryCtx)
			all := true
			for _, id := range jobs {
				job, e := services.Manager.GetJob(recoveryCtx, actor, id)
				if e != nil {
					all = false
					continue
				}
				if !domain.IsTerminal(text(job["state"])) {
					all = false
					continue
				}
				if job["purged"] != true {
					all = false
					_, e = services.Manager.Purge(recoveryCtx, actor, id, integer(job["version"]), domain.NewID())
					if e != nil {
						all = false
					}
				}
			}
			inventory, e := services.LocalNode.Inventory(recoveryCtx)
			if e == nil && chargedInventory(inventory) == 0 && all {
				allocations, queryErr := services.DB.All(recoveryCtx, "SELECT id FROM jm_allocations WHERE released_at IS NULL")
				project, projectErr := services.DB.One(recoveryCtx, "SELECT retained_bytes FROM jm_projects WHERE id = ?", "lifecycle")
				pending, pendingErr := services.DB.All(recoveryCtx, "SELECT id FROM jm_jobs WHERE purged_at IS NULL")
				if queryErr == nil && projectErr == nil && pendingErr == nil && len(allocations) == 0 && len(pending) == 0 && integer(project["retained_bytes"]) == 0 {
					report["recovery_physical_cleanup"] = physicalCleanup(recoveryCtx, t, services.LocalNode.Backend.(*executor.LinuxExecutor), inventory, jobs)
					schemaClean = true
					cleanupDone = true
					retainFixtureForRecovery = false
					break
				}
			}
			time.Sleep(250 * time.Millisecond)
		}
	}()
	for i := 0; i < 3; i++ {
		job, status, e := client.request(ctx, "POST", "/api/jobs/v1/jobs", jobSpec(fmt.Sprintf("Native Go federation %d", i+1), ready), 0)
		if e != nil || status != 202 {
			t.Fatalf("create job%d status%d: %v", i, status, e)
		}
		jobs = append(jobs, text(job["id"]))
	}
	report["job_ids"] = jobs
	foreign, e := http.NewRequestWithContext(ctx, "GET", api.URL+"/api/jobs/v1/jobs/"+jobs[0], nil)
	if e != nil {
		t.Fatal(e)
	}
	foreign.Header.Set("Authorization", "Bearer "+client.token("foreign"))
	denied, e := client.client.Do(foreign)
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, denied.Body)
	denied.Body.Close()
	if denied.StatusCode != 404 {
		t.Fatal("foreign job existence/content exposed")
	}
	report["foreign_job_denied"] = true
	report["source_commit"] = ready["source_commit"]
	report["dataset_sha256"] = ready["dataset_sha256"]
	report["fixture_versions"] = ready["fixture_versions"]
	report["exchange_runtime"] = ready["exchange_runtime"]
	allStarted := false
	queuedCancelled := false
	runningCancelled := false
	observed := []any{}
	lastSignature := ""
	lastProgress := time.Now()
	lastReceipt := time.Time{}
	for ctx.Err() == nil {
		if e = pass(ctx); e != nil {
			t.Fatalf("controller pass: %v", e)
		}
		select {
		case e := <-serviceErrors:
			if e != nil {
				t.Fatalf("managed ingress service: %v", e)
			} else {
				t.Fatal("managed ingress stopped")
			}
		default:
		}
		snapshots := []object{}
		for _, id := range jobs {
			j, e := client.get(ctx, id)
			if e != nil {
				t.Fatal(e)
			}
			snapshots = append(snapshots, j)
		}
		observed = append(observed, object{"time": time.Now().UTC().Format(time.RFC3339Nano), "jobs": []any{object{"state": snapshots[0]["state"], "phase": snapshots[0]["phase"], "round": snapshots[0]["current_round"]}, object{"state": snapshots[1]["state"], "phase": snapshots[1]["phase"], "round": snapshots[1]["current_round"]}, object{"state": snapshots[2]["state"], "phase": snapshots[2]["phase"], "round": snapshots[2]["current_round"]}}})
		if len(observed) > 2000 {
			observed = observed[len(observed)-2000:]
		}
		if text(snapshots[0]["state"]) == "RUNNING" && text(snapshots[1]["state"]) == "RUNNING" && text(snapshots[2]["state"]) == "QUEUED" {
			allStarted = true
			report["two_concurrent_jobs"] = true
			report["third_queued"] = true
		}
		if allStarted && !queuedCancelled {
			_, status, e := client.request(ctx, "POST", "/api/jobs/v1/jobs/"+jobs[2]+"/cancel", object{}, integer(snapshots[2]["version"]))
			if e != nil || status != 202 {
				t.Fatalf("queued cancellation status%d: %v", status, e)
			}
			queuedCancelled = true
			report["queued_cancelled"] = true
		}
		training := false
		if allStarted && !runningCancelled {
			var proof object
			training, proof, e = observedTraining(ctx, services, jobs[1])
			if e != nil {
				t.Fatal(e)
			}
			if training {
				report["training_cancellation_observation"] = proof
			}
		}
		if allStarted && !runningCancelled && training {
			_, status, e := client.request(ctx, "POST", "/api/jobs/v1/jobs/"+jobs[1]+"/cancel", object{}, integer(snapshots[1]["version"]))
			if e != nil || status != 202 {
				t.Fatalf("running cancellation status%d: %v", status, e)
			}
			runningCancelled = true
			report["training_cancelled"] = true
		}
		signatureData, _ := json.Marshal([]any{snapshots[0]["state"], snapshots[0]["phase"], snapshots[0]["current_round"], snapshots[1]["state"], snapshots[1]["phase"], snapshots[2]["state"]})
		signature := string(signatureData)
		if signature != lastSignature {
			lastSignature = signature
			lastProgress = time.Now()
		}
		if time.Since(lastReceipt) >= 5*time.Second {
			if e = privateJSON(filepath.Join(c.Root, "progress.json"), object{"stage": "training_and_cancellation", "states": obj(observed[len(observed)-1])["jobs"], "two_concurrent_jobs": allStarted, "queued_cancelled": queuedCancelled, "training_cancelled": runningCancelled}); e != nil {
				t.Fatal("private progress receipt failed")
			}
			lastReceipt = time.Now()
		}
		if time.Since(lastProgress) > 3*time.Minute {
			report["observations"] = observed
			t.Fatal("native lifecycle state stalled for three minutes")
		}
		if domain.IsTerminal(text(snapshots[0]["state"])) && text(snapshots[0]["state"]) != "SUCCEEDED" {
			report["observations"] = observed
			t.Fatalf("federation failed: %s/%s/%s", text(snapshots[0]["state"]), text(snapshots[0]["error_code"]), text(snapshots[0]["outcome_reason"]))
		}
		if text(snapshots[0]["state"]) == "SUCCEEDED" && text(snapshots[1]["state"]) == "CANCELLED" && text(snapshots[2]["state"]) == "CANCELLED" {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	report["observations"] = observed
	if ctx.Err() != nil {
		t.Fatal("full native lifecycle deadline")
	}
	if !allStarted || !queuedCancelled || !runningCancelled {
		t.Fatal("concurrency/queue/confirmed-training cancellation not observed")
	}
	first, e := client.get(ctx, jobs[0])
	if e != nil {
		t.Fatal(e)
	}
	if integer(first["current_round"]) != 2 {
		t.Fatal("absolute final round not reached")
	}
	history, status, e := client.request(ctx, "GET", "/api/jobs/v1/jobs?view=history", nil, 0)
	if e != nil || status != 200 || len(items(history["items"])) != 3 {
		t.Fatal("history must contain all three owned terminal jobs")
	}
	logs, status, e := client.request(ctx, "GET", "/api/jobs/v1/jobs/"+jobs[0]+"/logs", nil, 0)
	if e != nil || status != 200 || len(items(logs["items"])) == 0 {
		t.Fatal("terminal logs missing")
	}
	if e = privateJSON(filepath.Join(c.Root, "progress.json"), object{"stage": "artifact_verification", "two_concurrent_jobs": true, "queued_cancelled": true, "training_cancelled": true}); e != nil {
		t.Fatal("private progress receipt failed")
	}
	lineage := auditLineage(ctx, t, services, ready, jobs[0])
	report["lineage"] = lineage
	checkpointFound := false
	verified := []any{}
	cursor := ""
	for {
		path := "/api/jobs/v1/jobs/" + jobs[0] + "/artifacts?limit=100"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		page, status, e := client.request(ctx, "GET", path, nil, 0)
		if e != nil || status != 200 {
			t.Fatalf("artifact enumeration status%d: %v", status, e)
		}
		for _, raw := range items(page["items"]) {
			artifact := obj(raw)
			if !strings.HasSuffix(text(artifact["name"]), "model.safetensors") {
				continue
			}
			req, e := http.NewRequestWithContext(ctx, "GET", api.URL+"/api/jobs/v1/jobs/"+jobs[0]+"/artifacts/"+text(artifact["id"])+"/download", nil)
			if e != nil {
				t.Fatal(e)
			}
			req.Header.Set("Authorization", "Bearer "+client.token("owner"))
			response, e := client.client.Do(req)
			if e != nil {
				t.Fatal(e)
			}
			b, e := io.ReadAll(io.LimitReader(response.Body, 1<<20))
			response.Body.Close()
			if e != nil || response.StatusCode != 200 {
				t.Fatal("authenticated checkpoint download failed")
			}
			h := sha256.Sum256(b)
			digest := hex.EncodeToString(h[:])
			if digest != text(artifact["sha256"]) || int64(len(b)) != integer(artifact["size_bytes"]) {
				t.Fatal("download integrity mismatch")
			}
			value, e := checkpointValue(b)
			if e != nil {
				t.Fatal(e)
			}
			verified = append(verified, object{"artifact_id": artifact["id"], "sha256": digest, "value": value})
			if math.Abs(value-3.2) < 1e-5 {
				if digest != text(lineage["final_checkpoint_sha256"]) {
					t.Fatal("final download differs from authoritative main checkpoint")
				}
				checkpointFound = true
			}
		}
		cursor = text(page["next_cursor"])
		if cursor == "" {
			break
		}
	}
	report["verified_checkpoints"] = verified
	if !checkpointFound {
		t.Fatal("final 0.4/0.6 FedAvg checkpoint value3.2 not found")
	}
	if e = privateJSON(filepath.Join(c.Root, "progress.json"), object{"stage": "purging", "lineage_verified": true, "checkpoint_download_verified": true}); e != nil {
		t.Fatal("private progress receipt failed")
	}
	for _, id := range jobs {
		j, e := client.get(ctx, id)
		if e != nil {
			t.Fatal(e)
		}
		_, status, e := client.request(ctx, "POST", "/api/jobs/v1/jobs/"+id+"/purge", object{}, integer(j["version"]))
		if e != nil || status != 202 {
			t.Fatalf("purge status%d: %v", status, e)
		}
	}
	for ctx.Err() == nil {
		if e = pass(ctx); e != nil {
			t.Fatalf("purge controller: %v", e)
		}
		inventory, e := services.LocalNode.Inventory(ctx)
		if e != nil {
			t.Fatal(e)
		}
		row, e := services.DB.One(ctx, "SELECT retained_bytes FROM jm_projects WHERE id = ?", "lifecycle")
		if e != nil {
			t.Fatal(e)
		}
		allocations, e := services.DB.All(ctx, "SELECT id FROM jm_allocations WHERE released_at IS NULL")
		if e != nil {
			t.Fatal(e)
		}
		pending, e := services.DB.All(ctx, "SELECT id FROM jm_jobs WHERE purged_at IS NULL")
		if e != nil {
			t.Fatal(e)
		}
		if chargedInventory(inventory) == 0 && len(allocations) == 0 && len(pending) == 0 && integer(row["retained_bytes"]) == 0 {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if ctx.Err() != nil {
		t.Fatal("owned cleanup deadline")
	}
	report["two_concurrent_jobs"] = true
	report["third_queued"] = true
	report["queued_cancelled"] = true
	report["training_cancelled"] = true
	report["completed_rounds"] = 2
	report["fedavg_weights"] = []float64{.4, .6}
	inventory, e := services.LocalNode.Inventory(ctx)
	if e != nil {
		t.Fatal(e)
	}
	report["physical_cleanup"] = physicalCleanup(ctx, t, services.LocalNode.Backend.(*executor.LinuxExecutor), inventory, jobs)
	cleanupDone = true
	schemaClean = true
	report["owned_node_reservations"] = 0
	report["active_allocations"] = 0
	report["retained_bytes"] = 0
	report["status"] = "PASS"
}
