package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/exchange"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/httpapi"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/participants"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func participantAppFixture(t *testing.T) (*nodeAppFixture, exchange.NodePrincipal) {
	t.Helper()
	f := nodeAppDB(t)
	thumb := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	e := f.db.WithTx(f.ctx, true, func(tx *store.Tx) error {
		if e := tx.Insert(f.ctx, "jm_job_members", map[string]any{"job_id": "job", "principal_id": "owner", "role": "admin"}); e != nil {
			return e
		}
		return tx.Insert(f.ctx, "jm_participant_bindings", map[string]any{"id": "alice-data", "project_id": "project", "participant_id": "alice", "dataset_label": "Local approved images", "node_id": "external-node", "enabled": true})
	})
	if e != nil {
		t.Fatal(e)
	}
	s, e := participants.NewService(f.db, []participants.ApprovedNode{{NodeID: "external-node", CertificateThumbprint: thumb, DatasetBindings: map[string]map[string]any{"alice-data": {"kind": "synthetic"}}, Resources: map[string]int64{"cpu_millicores": 1000, "memory_bytes": 1 << 30, "disk_bytes": 1 << 30}, Enabled: true}}, participants.Hooks{}, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	f.services.Participants = s
	enrollment, e := s.Enroll(f.ctx, "owner", "job", "alice", "external-node", 1, "enroll")
	if e != nil {
		t.Fatal(e)
	}
	id := nodeString(enrollment["id"])
	row, e := f.db.One(f.ctx, "SELECT * FROM jm_provisioning_resources WHERE id=?", id)
	if e != nil {
		t.Fatal(e)
	}
	data := nodeObject(row["details_json"])
	data["status"] = "assigned"
	data["epoch"] = int64(1)
	data["termination_confirmed"] = false
	nodeAppUpdate(t, f, "jm_provisioning_resources", id, map[string]any{"attempt_id": "attempt", "details_json": data})
	actor := exchange.NodePrincipal{ID: "participant-principal", Subject: "participant-subject", NodeID: "external-node", PoolID: "external", JobID: "job", AttemptID: "attempt", ComponentID: domain.ExternalComponentID("alice"), GrantID: id, Epoch: 1, IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Minute).Unix(), CertificateThumbprint: thumb, Scopes: []string{"assignment", "heartbeat", "stopped"}}
	return f, actor
}
func TestParticipantAPIWiringChecksCurrentIdentityAndRevocation(t *testing.T) {
	f, actor := participantAppFixture(t)
	options := httpapi.Options{}
	if e := ConfigureNodeAPI(&options, f.services); e != nil {
		t.Fatal(e)
	}
	if options.ParticipantEnrollment == nil || options.ParticipantCall == nil || options.ParticipantAccessValid == nil {
		t.Fatal("participant ports not wired")
	}
	if _, e := options.ParticipantEnrollment(f.ctx, "foreign", "job", "alice"); e == nil {
		t.Fatal("foreign member could read enrollment")
	}
	if _, e := options.ParticipantEnrollment(f.ctx, "owner", "job", "alice"); e != nil {
		t.Fatal(e)
	}
	id := executor.ExecutionIdentity{JobID: actor.JobID, AttemptID: actor.AttemptID, ComponentID: actor.ComponentID, Epoch: actor.Epoch}
	mapped := executionActor(actor)
	valid, e := options.ParticipantAccessValid(f.ctx, "source", mapped)
	if e != nil || !valid {
		t.Fatalf("current source access denied %v %v", valid, e)
	}
	result, e := options.ParticipantCall(f.ctx, "heartbeat", mapped, id, map[string]any{"phase": "training", "current_round": json.Number("1")})
	if e != nil || result["accepted"] != true {
		t.Fatalf("heartbeat rejected %#v %v", result, e)
	}
	row, e := f.db.One(f.ctx, "SELECT * FROM jm_provisioning_resources WHERE id=?", actor.GrantID)
	if e != nil {
		t.Fatal(e)
	}
	if nodeNumber(nodeObject(row["details_json"])["current_round"]) != 1 {
		t.Fatal("round callback not persisted")
	}
	foreign := id
	foreign.ComponentID = "owner"
	_, e = options.ParticipantCall(f.ctx, "control", mapped, foreign, map[string]any{})
	nodeAppCode(t, e, "foreign_participant_assignment")
	result, e = options.ParticipantCall(f.ctx, "stopped", mapped, id, map[string]any{"termination_confirmed": true, "never_started": false})
	if e != nil || result["accepted"] != true {
		t.Fatalf("stop rejected %#v %v", result, e)
	}
	valid, e = options.ParticipantAccessValid(f.ctx, "source", mapped)
	if e != nil || valid {
		t.Fatalf("stopped execution kept source access %v %v", valid, e)
	}
	_, e = options.ParticipantCall(f.ctx, "heartbeat", mapped, id, map[string]any{"phase": "training"})
	if e == nil {
		t.Fatal("stopped assignment accepted new progress")
	}
}
func TestParticipantPortsAbsentWithoutConfiguredService(t *testing.T) {
	options := httpapi.Options{}
	if e := configureParticipantAPI(&options, &Services{}); e != nil {
		t.Fatal(e)
	}
	if options.ParticipantCall != nil || options.ParticipantOpen != nil || options.ParticipantEnroll != nil {
		t.Fatal("unconfigured service advertised participant authority")
	}
}
func TestParticipantAccessRejectsExpiredClaims(t *testing.T) {
	f, actor := participantAppFixture(t)
	options := httpapi.Options{}
	if e := configureParticipantAPI(&options, f.services); e != nil {
		t.Fatal(e)
	}
	actor.ExpiresAt = time.Now().Add(-time.Second).Unix()
	for _, operation := range []string{"source", "build-products"} {
		valid, e := options.ParticipantAccessValid(f.ctx, operation, executionActor(actor))
		if e != nil || valid {
			t.Fatalf("expired %s access accepted %v %v", operation, valid, e)
		}
	}
}
func TestStandaloneRoleConfigurationRejectsCentralCredentials(t *testing.T) {
	agent := map[string]any{"manager_endpoint": "https://manager.example", "manager_ca_file": "ca", "node_certificate": "cert", "node_key": "key", "certificate_ca_file": "execution-ca", "managed_exchange_endpoint": "https://exchange.example", "gateway_endpoint": "https://gateway.example", "service_ca_file": "service-ca", "manager_certificate_thumbprints": []string{strings.Repeat("A", 43)}, "catalog": map[string]any{}}
	node := map[string]any{"node_id": "alice-node", "pool_id": "external", "ledger_path": "/private/node-ledger", "capacity": map[string]any{}, "dataset_bindings": map[string]any{"alice-data": map[string]any{}}}
	settings := config.Settings{Workload: &config.WorkloadSettings{PublicKey: "verification-only"}, Extra: map[string]any{"node": node, "participants": map[string]any{"agent": agent}}}
	if _, _, e := standaloneSettings(settings, true); e != nil {
		t.Fatalf("role structure rejected before deep validation %v", e)
	}
	settings.Workload.PrivateKey = "signing-authority"
	if _, _, e := standaloneSettings(settings, true); e == nil {
		t.Fatal("participant accepted workload signing authority")
	}
	settings.Workload.PrivateKey = ""
	settings.Extra["provisioner"] = map[string]any{"exchange_token_file": "central-secret"}
	if _, _, e := standaloneSettings(settings, true); e == nil {
		t.Fatal("participant accepted central provisioner credentials")
	}
	delete(settings.Extra, "provisioner")
	node["pool_id"] = "managed-pool"
	if _, _, e := standaloneSettings(settings, true); e == nil {
		t.Fatal("external agent used a managed allocation pool")
	}
}
func TestLocalNodeCatalogRejectsUnapprovedShapes(t *testing.T) {
	base := map[string]any{"sources": []any{map[string]any{"source_id": "source", "projects": []string{"project"}, "commits": []string{strings.Repeat("a", 40)}, "url": "https://code.example/repo.git"}}, "runtime_images": map[string]any{"runtime": "sha256:" + strings.Repeat("b", 64)}, "allowed_source_hosts": []string{"code.example"}}
	catalog, e := localNodeCatalog(base)
	if e != nil || catalog.Registry == nil {
		t.Fatalf("trusted catalog rejected %v", e)
	}
	base["command"] = "execute"
	if _, e := localNodeCatalog(base); e == nil {
		t.Fatal("unknown local catalog authority accepted")
	}
	delete(base, "command")
	base["runtime_images"] = map[string]any{"runtime": "image:latest"}
	if _, e := localNodeCatalog(base); e == nil {
		t.Fatal("mutable runtime accepted")
	}
}
func TestParticipantUnconfiguredCompositionDoesNotStartServices(t *testing.T) {
	s := &Services{Settings: config.Settings{Extra: map[string]any{}}}
	if e := ComposeParticipants(context.Background(), s); e != nil {
		t.Fatal(e)
	}
	if s.Participants != nil || len(s.CloseCallbacks) != 0 {
		t.Fatal("unconfigured component started")
	}
	s.Settings.Extra["participants"] = map[string]any{"nodes": map[string]any{}}
	if e := ComposeParticipants(context.Background(), s); e == nil {
		t.Fatal("unconfigured provisioning accepted")
	}
}
