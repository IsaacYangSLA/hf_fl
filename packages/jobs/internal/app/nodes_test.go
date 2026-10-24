package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/controller"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/exchange"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/node"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/participants"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

type nodeAppFixture struct {
	ctx      context.Context
	db       *store.DB
	services *Services
	id       executor.ExecutionIdentity
	spec     domain.JobSpec
	digest   string
}

func nodeAppDB(t *testing.T) *nodeAppFixture {
	t.Helper()
	ctx := context.Background()
	db, e := store.Open(ctx, "sqlite:///"+filepath.Join(t.TempDir(), "node-app.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	if _, e = db.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	spec := domain.JobSpec{ProjectID: "project", Name: "Training", SourceID: "source", SourceCommit: strings.Repeat("a", 40), RuntimeImage: "runtime", Plugin: "example.trainer", Options: map[string]any{}, SecretRefs: map[string]string{}, Participants: []domain.ParticipantSpec{{ParticipantID: "alice", DatasetBinding: "alice-data", Mode: "external"}, {ParticipantID: "bob", DatasetBinding: "bob-data", Mode: "external"}}, Components: []domain.ComponentSpec{{ComponentID: "owner", Role: "owner", Resources: domain.ResourceRequest{PoolID: "cpu", CPUMillicores: 1000, MemoryBytes: 1 << 30, DiskBytes: 1 << 30, SandboxProfile: "runsc-cpu-v1"}}}, TargetRound: 2, MaxDurationSeconds: 3600}
	digest, e := spec.Digest()
	if e != nil {
		t.Fatal(e)
	}
	id := executor.ExecutionIdentity{JobID: "job", AttemptID: "attempt", ComponentID: "owner", Epoch: 1}
	e = db.WithTx(ctx, true, func(tx *store.Tx) error {
		for _, item := range []struct {
			table string
			row   map[string]any
		}{
			{"jm_projects", map[string]any{"id": "project", "name": "Project"}},
			{"jm_jobs", map[string]any{"id": "job", "project_id": "project", "creator_id": "owner", "name": "Training", "spec_json": spec.Map(), "spec_hash": digest, "target_round": int64(2), "state": "RUNNING", "phase": "training", "current_attempt": int64(1), "attempt_count": int64(1), "epoch": int64(1), "deadline_at": time.Now().UTC().Add(time.Hour)}},
			{"jm_attempts", map[string]any{"id": "attempt", "job_id": "job", "number": int64(1), "epoch": int64(1), "state": "RUNNING", "resources_json": map[string]any{}}},
			{"jm_pools", map[string]any{"id": "cpu", "name": "CPU", "node_id": "worker-node", "cpu_millicores": int64(4000), "memory_bytes": int64(4 << 30), "disk_bytes": int64(4 << 30), "healthy": true, "sandbox_profiles": []string{"runsc-cpu-v1"}}},
			{"jm_allocations", map[string]any{"id": "allocation", "job_id": "job", "attempt_id": "attempt", "component_id": "owner", "pool_id": "cpu", "cpu_millicores": int64(1000), "memory_bytes": int64(1 << 30), "disk_bytes": int64(1 << 30), "epoch": int64(1), "state": "RUNNING", "acknowledged": true, "details_json": map[string]any{"node_id": "worker-node"}}},
		} {
			if e := tx.Insert(ctx, item.table, item.row); e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	s := &Services{DB: db, Settings: config.Settings{Extra: map[string]any{"node": map[string]any{"node_id": "worker-node", "pool_id": "cpu"}}}, Controller: controller.New(db, nil, nil)}
	return &nodeAppFixture{ctx, db, s, id, spec, digest}
}
func nodeAppUpdate(t *testing.T, f *nodeAppFixture, table, id string, values map[string]any) {
	t.Helper()
	if e := f.db.WithTx(f.ctx, true, func(tx *store.Tx) error { return tx.Update(f.ctx, table, map[string]any{"id": id}, values) }); e != nil {
		t.Fatal(e)
	}
}
func nodeAppCode(t *testing.T, e error, want string) {
	t.Helper()
	var coded *domain.Error
	if !errors.As(e, &coded) || coded.Code != want {
		t.Fatalf("expected %s, got %v", want, e)
	}
}
func TestNodeAdmissionPinsResourcesAndHistoricalPlacement(t *testing.T) {
	f := nodeAppDB(t)
	a, e := nodeAdmission(f.ctx, f.services, f.id, "cpu")
	if e != nil {
		t.Fatal(e)
	}
	if a.Route.NodeID != "worker-node" || a.Route.Resources.CPUMillis != 1000 {
		t.Fatalf("wrong route %#v", a.Route)
	}
	nodeAppUpdate(t, f, "jm_pools", "cpu", map[string]any{"node_id": "replacement-node"})
	a, e = nodeAdmission(f.ctx, f.services, f.id, "cpu")
	if e != nil || a.Route.NodeID != "worker-node" {
		t.Fatalf("historical placement moved %#v %v", a.Route, e)
	}
	_, e = nodeAdmission(f.ctx, f.services, f.id, "other")
	nodeAppCode(t, e, "pool_mismatch")
	nodeAppUpdate(t, f, "jm_allocations", "allocation", map[string]any{"cpu_millicores": int64(2000)})
	_, e = nodeAdmission(f.ctx, f.services, f.id, "cpu")
	nodeAppCode(t, e, "invalid_resources")
}
func TestRemoteSourcePrepaymentRequiresBothExactCharges(t *testing.T) {
	for _, which := range []string{"missing", "valid", "released", "foreign-attempt", "duplicate", "unbounded-source"} {
		t.Run(which, func(t *testing.T) {
			f := nodeAppDB(t)
			a, e := nodeAdmission(f.ctx, f.services, f.id, "cpu")
			if e != nil {
				t.Fatal(e)
			}
			if which != "missing" {
				e = f.db.WithTx(f.ctx, true, func(tx *store.Tx) error {
					for _, scope := range []string{"shared", "attempt_private"} {
						d := map[string]any{"node_id": "worker-node", "pool_id": "cpu", "spec_digest": f.digest, "retention_charged_bytes": int64(4096), "retention_charge_released": false, "scope": scope, "attempt_number": int64(1), "source_limits": map[string]any{"max_bytes": int64(1024), "max_files": int64(20), "max_git_bytes": int64(4096), "max_git_files": int64(100)}}
						if which == "released" && scope == "shared" {
							d["retention_charge_released"] = true
						}
						if which == "foreign-attempt" && scope == "attempt_private" {
							d["attempt_number"] = int64(2)
						}
						if which == "unbounded-source" && scope == "shared" {
							d["source_limits"] = map[string]any{"max_bytes": int64(1024)}
						}
						if e := tx.Insert(f.ctx, "jm_provisioning_resources", map[string]any{"id": scope, "job_id": "job", "attempt_id": "attempt", "component_id": "owner", "kind": "remote_auxiliary", "details_json": d}); e != nil {
							return e
						}
						if which == "duplicate" && scope == "shared" {
							if e := tx.Insert(f.ctx, "jm_provisioning_resources", map[string]any{"id": "duplicate", "job_id": "job", "attempt_id": "attempt", "component_id": "owner", "kind": "remote_auxiliary", "details_json": d}); e != nil {
								return e
							}
						}
					}
					return nil
				})
				if e != nil {
					t.Fatal(e)
				}
			}
			bounds, e := prepaidRemoteSource(f.ctx, f.services, a, f.id)
			if which == "valid" {
				if e != nil || bounds["max_bytes"] != 1024 {
					t.Fatalf("valid charges rejected %v %v", bounds, e)
				}
			} else {
				nodeAppCode(t, e, "source_capacity_not_reserved")
			}
		})
	}
}
func nodeAppLocalActor() exchange.NodePrincipal {
	return exchange.NodePrincipal{ID: "node-principal", NodeID: "worker-node", PoolID: "cpu", JobID: "job", AttemptID: "attempt", ComponentID: "owner", GrantID: "allocation", Epoch: 1, CertificateThumbprint: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Scopes: []string{"heartbeat"}, Resources: map[string]any{"cpu_millicores": int64(1000), "memory_bytes": int64(1 << 30), "disk_bytes": int64(1 << 30)}}
}
func TestNodeGrantUsesSelectedDurableAuthority(t *testing.T) {
	f := nodeAppDB(t)
	actor := nodeAppLocalActor()
	valid, e := CurrentNodeGrant(f.ctx, f.services, actor)
	if e != nil || !valid {
		t.Fatalf("local grant rejected %v %v", valid, e)
	}
	actor.GrantID = "unissued"
	valid, e = CurrentNodeGrant(f.ctx, f.services, actor)
	if e != nil || valid {
		t.Fatalf("unissued grant accepted %v %v", valid, e)
	}
	actor = nodeAppLocalActor()
	actor.Resources["cpu_millicores"] = int64(999)
	valid, e = CurrentNodeGrant(f.ctx, f.services, actor)
	if e != nil || valid {
		t.Fatalf("foreign limits accepted %v %v", valid, e)
	}
	actor = nodeAppLocalActor()
	actor.NodeID = "unapproved"
	valid, e = CurrentNodeGrant(f.ctx, f.services, actor)
	if e != nil || valid {
		t.Fatalf("unapproved node accepted %v %v", valid, e)
	}
	// A selected managed-node refusal is final; the local controller cannot
	// authorize that managed identity through a second path.
	actor = nodeAppLocalActor()
	f.services.ManagedNodes = &node.AssignmentService{DB: f.db, Config: node.AssignmentConfig{RegisteredNodes: map[string]node.ApprovedManagedNode{"worker-node": {NodeID: "worker-node", PoolID: "cpu", RegistrationID: "registration", CertificateThumbprint: actor.CertificateThumbprint, Enabled: true}}, ManagerCertificateThumbprint: strings.Repeat("x", 43), Clock: time.Now}}
	actor.CertificateThumbprint = strings.Repeat("y", 43)
	valid, e = CurrentNodeGrant(f.ctx, f.services, actor)
	if valid {
		t.Fatalf("managed refusal fell back: %v %v", valid, e)
	}
}
func TestMixedTopologyRoutesExternalEnrollmentToItsAuthority(t *testing.T) {
	f := nodeAppDB(t)
	thumb := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	actor := exchange.NodePrincipal{ID: "participant-node", NodeID: "external-node", PoolID: "external", JobID: "job", AttemptID: "attempt", ComponentID: domain.ExternalComponentID("alice"), GrantID: "external-grant", Epoch: 1, CertificateThumbprint: thumb, Scopes: []string{"assignment"}, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	// Unrelated managed registrations must not be consulted for an external
	// enrollment grant. Its persisted kind selects the participant authority.
	f.services.ManagedNodes = &node.AssignmentService{DB: f.db, Config: node.AssignmentConfig{RegisteredNodes: map[string]node.ApprovedManagedNode{}, Clock: time.Now}}
	f.services.Participants = &participants.Service{DB: f.db, Clock: time.Now, Nodes: map[string]participants.ApprovedNode{"external-node": {NodeID: "external-node", CertificateThumbprint: thumb, DatasetBindings: map[string]map[string]any{"alice-data": {"kind": "synthetic"}}, Resources: map[string]int64{"cpu_millicores": 1000, "memory_bytes": 1 << 30, "disk_bytes": 1 << 30}, Enabled: true}}}
	e := f.db.WithTx(f.ctx, true, func(tx *store.Tx) error {
		if e := tx.Insert(f.ctx, "jm_participant_bindings", map[string]any{"id": "alice-data", "project_id": "project", "participant_id": "alice", "dataset_label": "Approved data", "node_id": "external-node", "enabled": true}); e != nil {
			return e
		}
		return tx.Insert(f.ctx, "jm_provisioning_resources", map[string]any{"id": "external-grant", "job_id": "job", "attempt_id": "attempt", "component_id": actor.ComponentID, "kind": "external_enrollment", "state": "ready", "details_json": map[string]any{"participant_id": "alice", "node_id": "external-node", "node_certificate_thumbprint": thumb, "dataset_binding": "alice-data", "spec_digest": f.digest, "status": "assigned", "epoch": int64(1)}})
	})
	if e != nil {
		t.Fatal(e)
	}
	valid, e := CurrentNodeGrant(f.ctx, f.services, actor)
	if e != nil || !valid {
		t.Fatalf("valid external grant rejected %v %v", valid, e)
	}
	actor.CertificateThumbprint = strings.Repeat("x", 43)
	valid, e = CurrentNodeGrant(f.ctx, f.services, actor)
	if e != nil || valid {
		t.Fatalf("foreign external certificate accepted %v %v", valid, e)
	}
	actor.CertificateThumbprint = thumb
	nodeAppUpdate(t, f, "jm_provisioning_resources", "external-grant", map[string]any{"state": "deleted"})
	valid, e = CurrentNodeGrant(f.ctx, f.services, actor)
	if e != nil || valid {
		t.Fatalf("revoked enrollment accepted %v %v", valid, e)
	}
}
func TestNodeGrantDatabaseFailureDoesNotFallback(t *testing.T) {
	f := nodeAppDB(t)
	_ = f.db.Close()
	valid, e := CurrentNodeGrant(f.ctx, f.services, nodeAppLocalActor())
	if e == nil || valid {
		t.Fatalf("database failure accepted %v %v", valid, e)
	}
}
func TestExecutionActorPreservesVerifiedClaimsAndCopiesResources(t *testing.T) {
	p := nodeAppLocalActor()
	p.Subject = "subject"
	p.IssuedAt = 100
	p.ExpiresAt = 200
	p.Resources["cpu_millicores"] = json.Number("1000")
	a := executionActor(p)
	roundtrip := nodePrincipal(a)
	if !nodeSame(p, roundtrip) {
		t.Fatal("verified claims lost in HTTP adapter")
	}
	a.Resources["cpu_millicores"] = json.Number("999")
	if nodeNumber(p.Resources["cpu_millicores"]) != 1000 {
		t.Fatal("HTTP actor aliases verified resource claims")
	}
}
func TestRegisteredExecutorRefusesPlacementSubstitution(t *testing.T) {
	r := &RegisteredExecutor{Route: func(context.Context, executor.ExecutionIdentity, string) (node.NodeRoute, error) {
		return node.NodeRoute{NodeID: "missing", PoolID: "cpu"}, nil
	}, Endpoints: map[string]node.NodeEndpoint{}}
	_, _, e := r.selectExecutor(context.Background(), executor.ExecutionIdentity{JobID: "job", AttemptID: "attempt", ComponentID: "owner", Epoch: 1}, "cpu")
	nodeAppCode(t, e, "node_not_approved")
}
func TestNodeBoundaryDefaultsAndUnknownFields(t *testing.T) {
	legacy := map[string]any{"certificate": "cert.pem", "key": "key.pem", "client_ca": "ca.pem"}
	boundary, e := normalizedNodeBoundary(legacy, 9444)
	if e != nil {
		t.Fatal(e)
	}
	if boundary["tls_certificate"] != "cert.pem" || boundary["port"] != int64(9444) {
		t.Fatal(boundary)
	}
	legacy["tls_key"] = "ambiguous"
	if _, e = normalizedNodeBoundary(legacy, 9444); e == nil {
		t.Fatal("mixed TLS boundary aliases accepted")
	}
}

func TestComposeNodesWithoutExecutorsKeepsNilPort(t *testing.T) {
	services := &Services{Settings: config.Settings{Extra: map[string]any{}}}
	if e := ComposeNodes(context.Background(), services, false); e != nil {
		t.Fatal(e)
	}
	if services.Node != nil || services.Remote != nil || services.LocalNode != nil {
		t.Fatal("unconfigured executor advertised a typed nil port")
	}
	if e := ComposeNodes(context.Background(), services, true); e == nil {
		t.Fatal("controller accepted no executor")
	}
}

func TestRemoteAuxiliaryPlansFreshBoundsWithinAdmissionTransaction(t *testing.T) {
	f := nodeAppDB(t)
	f.services.Settings.Extra["nodes"] = map[string]any{"endpoints": map[string]any{"worker-node": map[string]any{"pool_id": "cpu"}}}
	var job map[string]any
	err := f.db.WithTx(f.ctx, true, func(tx *store.Tx) error {
		if e := tx.Insert(f.ctx, "jm_approved_sources", map[string]any{"id": "source", "project_id": "project", "name": "Source", "url": "https://example.com/trainer.git", "status": "approved", "enabled": true, "allowed_commits": []string{strings.Repeat("a", 40)}, "allowed_hosts": []string{"example.com"}, "details_json": map[string]any{"max_bytes": int64(1024), "max_files": int64(10), "max_git_bytes": int64(2048), "max_git_files": int64(20)}}); e != nil {
			return e
		}
		var e error
		job, e = tx.One(f.ctx, "SELECT * FROM jm_jobs WHERE id=?", "job")
		if e != nil {
			return e
		}
		plans, e := RemoteAuxiliaryStorageTx(f.ctx, f.services, tx, job)
		if e != nil {
			return e
		}
		if len(plans) != 2 || plans[0]["max_bytes"] != int64(1024+8192*(3*10+1024)+2048+8192*(3*20+1024)) || plans[1]["max_bytes"] != int64((4<<20)+(256<<10)) {
			t.Fatalf("wrong plans %#v", plans)
		}
		if nodeObject(plans[0]["details"])["spec_digest"] != f.digest || plans[1]["external_id"] != "hf2l-node-inputs://worker-node/job/owner/attempt/1" {
			t.Fatalf("unbound plans %#v", plans)
		}

		withBuild := f.spec
		withBuild.Components = append(append([]domain.ComponentSpec(nil), f.spec.Components...), domain.ComponentSpec{ComponentID: "builder", Role: "build", Resources: f.spec.Components[0].Resources})
		buildDigest, e := withBuild.Digest()
		if e != nil {
			return e
		}
		buildJob := map[string]any{}
		for key, value := range job {
			buildJob[key] = value
		}
		buildJob["spec_json"], buildJob["spec_hash"] = withBuild.Map(), buildDigest
		buildPlans, e := RemoteAuxiliaryStorageTx(f.ctx, f.services, tx, buildJob)
		if e != nil {
			return e
		}
		if len(buildPlans) != 4 || buildPlans[0]["max_bytes"] != plans[0]["max_bytes"].(int64)+(256<<20)+8192*5 || buildPlans[2]["max_bytes"] != plans[0]["max_bytes"] {
			t.Fatalf("build staging not prepaid by component role: %#v", buildPlans)
		}
		if e = tx.Update(f.ctx, "jm_approved_sources", map[string]any{"id": "source"}, map[string]any{"enabled": false}); e != nil {
			return e
		}
		if _, e = RemoteAuxiliaryStorageTx(f.ctx, f.services, tx, job); e == nil {
			t.Fatal("stale source approval accepted")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
func TestRemoteAuxiliaryPlansRejectMalformedBoundsAndPool(t *testing.T) {
	for _, which := range []string{"numeric-string", "wrong-pool", "disabled"} {
		t.Run(which, func(t *testing.T) {
			f := nodeAppDB(t)
			registration := map[string]any{"pool_id": "cpu"}
			if which == "wrong-pool" {
				registration["pool_id"] = "foreign"
			}
			if which == "disabled" {
				registration["enabled"] = false
			}
			f.services.Settings.Extra["nodes"] = map[string]any{"endpoints": map[string]any{"worker-node": registration}}
			bound := any(int64(1024))
			if which == "numeric-string" {
				bound = "1024"
			}
			e := f.db.WithTx(f.ctx, true, func(tx *store.Tx) error {
				if e := tx.Insert(f.ctx, "jm_approved_sources", map[string]any{"id": "source", "project_id": "project", "name": "Source", "url": "https://example.com/trainer.git", "status": "approved", "enabled": true, "allowed_commits": []string{strings.Repeat("a", 40)}, "allowed_hosts": []string{"example.com"}, "details_json": map[string]any{"max_bytes": bound}}); e != nil {
					return e
				}
				job, e := tx.One(f.ctx, "SELECT * FROM jm_jobs WHERE id=?", "job")
				if e != nil {
					return e
				}
				_, e = RemoteAuxiliaryStorageTx(f.ctx, f.services, tx, job)
				if e == nil {
					t.Fatal("unsafe remote staging plan accepted")
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
		})
	}
}

type receiptExecutor struct {
	controller.Executor
	calls []executor.ExecutionIdentity
	wrong bool
}

func (r *receiptExecutor) IsRemote(context.Context, executor.ExecutionIdentity) (bool, error) {
	return true, nil
}
func (r *receiptExecutor) PurgeReceipt(ctx context.Context, id executor.ExecutionIdentity, digest string) (node.NodePurgeReceipt, error) {
	r.calls = append(r.calls, id)
	nodeID := "worker-node"
	if r.wrong {
		nodeID = "foreign-node"
	}
	return node.NodePurgeReceipt{JobID: id.JobID, AttemptID: id.AttemptID, ComponentID: id.ComponentID, Epoch: id.Epoch, NodeID: nodeID, PoolID: "cpu", SpecDigest: digest, OperationID: "purge-" + id.Key(), Purpose: "managed_node_purge", TerminationConfirmed: true, SourceDeleted: true, ConfigDeleted: true, BuildDeleted: true, PrivateCredentialsDeleted: true, PrivateSecretsDeleted: true, RetainedDeleted: true, AuxiliaryDeleted: true, Confirmed: true}, nil
}
func TestRemoteAuxiliaryCleanupRequiresEveryHistoricalAllocationReceipt(t *testing.T) {
	f := nodeAppDB(t)
	backend := &receiptExecutor{}
	f.services.Node = backend
	e := f.db.WithTx(f.ctx, true, func(tx *store.Tx) error {
		if e := tx.Insert(f.ctx, "jm_attempts", map[string]any{"id": "past-attempt", "job_id": "job", "number": int64(2), "epoch": int64(2), "state": "CANCELLED", "resources_json": map[string]any{}}); e != nil {
			return e
		}
		return tx.Insert(f.ctx, "jm_allocations", map[string]any{"id": "past-allocation", "job_id": "job", "attempt_id": "past-attempt", "component_id": "owner", "pool_id": "cpu", "cpu_millicores": int64(1000), "memory_bytes": int64(1 << 30), "disk_bytes": int64(1 << 30), "epoch": int64(2), "state": "RELEASED", "released_at": time.Now().UTC(), "details_json": map[string]any{"node_id": "worker-node"}})
	})
	if e != nil {
		t.Fatal(e)
	}
	var job map[string]any
	e = f.db.WithTx(f.ctx, false, func(tx *store.Tx) error {
		var e error
		job, e = tx.One(f.ctx, "SELECT * FROM jm_jobs WHERE id=?", "job")
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	resource := map[string]any{"id": "auxiliary", "component_id": "owner", "details": map[string]any{"node_id": "worker-node", "pool_id": "cpu", "spec_digest": f.digest}}
	proofs, e := RemoteAuxiliaryCleanup(f.ctx, f.services, job, []map[string]any{resource})
	if e != nil {
		t.Fatal(e)
	}
	if len(proofs["auxiliary"]) != 2 || len(backend.calls) != 2 {
		t.Fatalf("missing historical receipts %#v %#v", proofs, backend.calls)
	}
	if _, ok := proofs["auxiliary"][0]["epoch"].(json.Number); !ok {
		t.Fatalf("receipt integer lost its exact representation %#v", proofs)
	}
	backend.wrong = true
	if _, e = RemoteAuxiliaryCleanup(f.ctx, f.services, job, []map[string]any{resource}); e == nil {
		t.Fatal("foreign-node receipt accepted")
	}
	backend.wrong = false
	resource["details"] = map[string]any{"node_id": "absent-node", "pool_id": "cpu", "spec_digest": f.digest}
	if _, e = RemoteAuxiliaryCleanup(f.ctx, f.services, job, []map[string]any{resource}); e == nil {
		t.Fatal("unproved physical cleanup accepted")
	}
}
