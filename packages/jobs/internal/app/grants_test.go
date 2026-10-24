package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/exchange"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/transfer"
)

func grantFixture(t *testing.T, mutate func(*store.DB) error) (*Services, *exchange.Client, transfer.ExecutionBinding) {
	t.Helper()
	ctx := context.Background()
	db, e := store.Open(ctx, "sqlite:///"+filepath.Join(t.TempDir(), "grant.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	if _, e = db.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	raw := []byte(`{"project_id":"project","name":"job","source_id":"source","source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","runtime_image":"image","plugin":"lenet","components":[{"component_id":"owner","role":"owner","resources":{"pool_id":"cpu","cpu_millicores":1000,"memory_bytes":1048576,"disk_bytes":1048576}}],"target_round":2,"max_duration_seconds":3600}`)
	spec, e := domain.DecodeJobSpec(raw)
	if e != nil {
		t.Fatal(e)
	}
	digest, e := spec.Digest()
	if e != nil {
		t.Fatal(e)
	}
	e = db.WithTx(ctx, true, func(tx *store.Tx) error {
		for _, entry := range []struct {
			table  string
			values map[string]any
		}{
			{"jm_projects", map[string]any{"id": "project", "name": "Project"}},
			{"jm_jobs", map[string]any{"id": "job", "project_id": "project", "creator_id": "actor", "name": "Job", "spec_json": spec.Map(), "spec_hash": digest, "state": "RUNNING", "epoch": int64(1), "current_attempt": int64(1), "attempt_count": int64(1), "target_round": int64(2), "deadline_at": time.Now().Add(time.Hour)}},
			{"jm_attempts", map[string]any{"id": "attempt", "job_id": "job", "number": int64(1), "epoch": int64(1), "state": "RUNNING"}},
			{"jm_provisioning_resources", map[string]any{"id": "resource", "job_id": "job", "attempt_id": "attempt", "component_id": "owner", "kind": "workload_grant", "external_id": "grant", "state": "active", "details_json": map[string]any{"space_id": "space"}}},
		} {
			if e := tx.Insert(ctx, entry.table, entry.values); e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	binding := transfer.ExecutionBinding{JobID: "job", AttemptID: "attempt", ComponentID: "owner", Epoch: 1, SpaceID: "space", CertificateThumbprint: strings.Repeat("A", 43)}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v2/spaces/space/workload-grants/grant" {
			t.Error("unexpected Exchange grant request", r.Method, r.URL.Path)
			w.WriteHeader(404)
			return
		}
		if mutate != nil {
			if e := mutate(db); e != nil {
				t.Error(e)
				w.WriteHeader(500)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"job_id": "job", "attempt_id": "attempt", "component_id": "owner", "space_id": "space", "certificate_thumbprint": binding.CertificateThumbprint, "epoch": 1, "expires_at": time.Now().Add(time.Minute).Unix(), "revoked_at": nil, "enabled": true})
	}))
	t.Cleanup(origin.Close)
	client, e := exchange.New(exchange.Config{Endpoint: origin.URL, Token: "test-admin", AllowLocalHTTP: true})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(client.Close)
	return &Services{DB: db}, client, binding
}
func TestCurrentGrantRechecksManagerAuthorityAfterNetworkLookup(t *testing.T) {
	ctx := context.Background()
	mutations := map[string]func(*store.DB) error{
		"active_control": nil,
		"cancelled": func(db *store.DB) error {
			_, e := db.Exec(ctx, "UPDATE jm_jobs SET state = ? WHERE id = ?", "CANCELLING", "job")
			return e
		},
		"successor_epoch": func(db *store.DB) error {
			_, e := db.Exec(ctx, "UPDATE jm_jobs SET epoch = ?, current_attempt = ? WHERE id = ?", int64(2), int64(2), "job")
			return e
		},
		"grant_resource_deleted": func(db *store.DB) error {
			_, e := db.Exec(ctx, "UPDATE jm_provisioning_resources SET state = ? WHERE id = ?", "deleted", "resource")
			return e
		},
		"grant_resource_rebound": func(db *store.DB) error {
			return db.WithTx(ctx, true, func(tx *store.Tx) error {
				return tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": "resource"}, map[string]any{"details_json": map[string]any{"space_id": "foreign"}})
			})
		},
		"deadline_expired": func(db *store.DB) error {
			_, e := db.Exec(ctx, "UPDATE jm_jobs SET deadline_at = ? WHERE id = ?", store.UTC(time.Now().Add(-time.Minute)), "job")
			return e
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			services, client, binding := grantFixture(t, mutate)
			grant, _, e := currentGrant(ctx, services, client, binding)
			if name == "active_control" {
				if e != nil || grant["id"] != "grant" {
					t.Fatal(grant, e)
				}
			} else if e == nil {
				t.Fatal("stale manager binding survived network lookup", name, grant)
			}
		})
	}
}
func TestTokenSigningRechecksManagerBindingAfterLookup(t *testing.T) {
	ctx := context.Background()
	services, client, binding := grantFixture(t, nil)
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	pub, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	broker, e := exchange.NewBroker(exchange.BrokerSettings{Issuer: "urn:hf2l:workloads", ExchangeAudience: "exchange-managed", GatewayAudience: "hf2l-transfer", NodeAudience: "hf2l-nodes", PublicKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})})
	if e != nil {
		t.Fatal(e)
	}
	services.Broker = broker
	grant, participant, e := currentGrant(ctx, services, client, binding)
	if e != nil {
		t.Fatal(e)
	}
	token, e := issueCurrentWorkload(ctx, services, binding, grant, participant, false)
	if e != nil || token == "" {
		t.Fatal("active signing control failed", e)
	}
	if _, e = broker.AuthenticateWorkload("Bearer "+token, binding.CertificateThumbprint, "exchange"); e != nil {
		t.Fatal(e)
	}
	if _, e = services.DB.Exec(ctx, "UPDATE jm_jobs SET state = ? WHERE id = ?", "CANCELLING", "job"); e != nil {
		t.Fatal(e)
	}
	token, e = issueCurrentWorkload(ctx, services, binding, grant, participant, false)
	if e == nil || token != "" {
		t.Fatal("minted fresh credential after cancellation", e)
	}
}
