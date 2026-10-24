package controller

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

type publicationTestExchange struct {
	mainID      string
	records     map[string]map[string]any
	acquisition map[string]any
}

func (x *publicationTestExchange) GetReference(ctx context.Context, space, ref string) (map[string]any, error) {
	if x.mainID == "" {
		return nil, domain.Err(404, "reference_not_found")
	}
	return map[string]any{"record_id": x.mainID}, nil
}
func (x *publicationTestExchange) GetRecord(ctx context.Context, space, id string) (map[string]any, error) {
	if item := x.records[id]; item != nil {
		return item, nil
	}
	return nil, domain.Err(404, "record_not_found")
}
func (x *publicationTestExchange) GetAcquisition(ctx context.Context, space, id string) (map[string]any, error) {
	if x.acquisition == nil {
		return nil, domain.Err(404, "acquisition_not_found")
	}
	return x.acquisition, nil
}

type publicationTestState struct {
	files      map[string][]byte
	identities []executor.ExecutionIdentity
	names      []string
	err        error
	oversize   bool
}

func (s *publicationTestState) ReadState(ctx context.Context, id executor.ExecutionIdentity, name string, limit int64) ([]byte, error) {
	s.identities = append(s.identities, id)
	s.names = append(s.names, name)
	if s.err != nil {
		return nil, s.err
	}
	if s.oversize {
		return make([]byte, limit+1), nil
	}
	if b, ok := s.files[name]; ok {
		return b, nil
	}
	return nil, fs.ErrNotExist
}

type publicationTestFixture struct {
	db               *store.DB
	ctx              context.Context
	job, attempt     map[string]any
	observer         *AuthoritativePublicationObserver
	exchange         *publicationTestExchange
	state, external  *publicationTestState
	manifest, intent map[string]any
	component        string
}

func publicationTestBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, err := domain.CanonicalJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func publicationTestFixtureNew(t *testing.T, external bool) *publicationTestFixture {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, "sqlite:///"+filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	participants := []any{}
	if external {
		participants = append(participants, map[string]any{"participant_id": "alice", "dataset_binding": "alice-local", "mode": "external"})
	}
	spec, err := domain.DecodeJobSpec(publicationTestBytes(t, map[string]any{"project_id": "project", "name": "Publication test", "source_id": "approved", "source_commit": strings.Repeat("a", 40), "runtime_image": "sha256:" + strings.Repeat("b", 64), "plugin": "lenet", "options": map[string]any{}, "participants": participants, "components": []any{map[string]any{"component_id": "owner", "role": "owner", "resources": map[string]any{"pool_id": "cpu", "cpu_millicores": 1000, "memory_bytes": 1048576, "disk_bytes": 1048576}}}, "target_round": 1, "max_duration_seconds": 3600}))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := spec.Digest()
	if err != nil {
		t.Fatal(err)
	}
	job := map[string]any{"id": "job", "project_id": "project", "creator_id": "human", "name": "Publication test", "spec_json": spec.Map(), "spec_hash": digest, "target_round": int64(1), "current_attempt": int64(1), "epoch": int64(1), "state": "RECONCILING"}
	attempt := map[string]any{"id": "attempt", "job_id": "job", "number": int64(1), "epoch": int64(1), "revocation_confirmed": true}
	err = db.WithTx(ctx, true, func(tx *store.Tx) error {
		if err := tx.Insert(ctx, "jm_projects", map[string]any{"id": "project", "name": "Project"}); err != nil {
			return err
		}
		if err := tx.Insert(ctx, "jm_jobs", job); err != nil {
			return err
		}
		if err := tx.Insert(ctx, "jm_attempts", attempt); err != nil {
			return err
		}
		if err := tx.Insert(ctx, "jm_pools", map[string]any{"id": "cpu", "name": "CPU", "node_id": "node"}); err != nil {
			return err
		}
		if err := tx.Insert(ctx, "jm_allocations", map[string]any{"id": "allocation", "job_id": "job", "attempt_id": "attempt", "component_id": "owner", "pool_id": "cpu", "cpu_millicores": int64(1000), "memory_bytes": int64(1048576), "disk_bytes": int64(1048576), "epoch": int64(1), "termination_confirmed": true}); err != nil {
			return err
		}
		for _, op := range []string{"start", "revoke", "stop"} {
			if err := tx.Insert(ctx, "jm_provisioning_operations", map[string]any{"id": op, "job_id": "job", "attempt_id": "attempt", "component_id": "owner", "operation": op, "idempotency_key": op, "state": "confirmed"}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{"round": int64(0), "checkpoint_files_sha256": map[string]any{"weights.safetensors": strings.Repeat("a", 64)}}
	manifestBytes := publicationTestBytes(t, manifest)
	intent := map[string]any{"phase": "publishing", "binding": map[string]any{"job_id": "job"}, "manifest_sha256": publicationHash(manifestBytes), "checkpoint_files_sha256": map[string]any{"weights.safetensors": strings.Repeat("a", 64)}}
	state := &publicationTestState{files: map[string][]byte{
		"progress.json":                      publicationTestBytes(t, map[string]any{"job_id": "job", "component_id": "owner", "phase": "initializing"}),
		"initialization.json":                publicationTestBytes(t, intent),
		"initial-model.exchange-upload.json": publicationTestBytes(t, map[string]any{"record_id": "record", "key": "upload-key"}),
		"initial-model/fedavg_round.json":    manifestBytes,
	}}
	record := map[string]any{"id": "record", "space_id": "space", "creator": "owner-principal", "creator_bindings": map[string]any{}, "kind": "model.global", "state": "published", "attachments": []any{map[string]any{"path": "weights.safetensors", "sha256": strings.Repeat("a", 64)}}, "metadata": map[string]any{"hf2l_files": map[string]any{"fedavg_round.json": manifest}}}
	exchange := &publicationTestExchange{mainID: "record", records: map[string]map[string]any{"record": record}}
	observer := &AuthoritativePublicationObserver{DB: db, Exchange: exchange, StateReader: state, Principal: func(job, component, participant string) string {
		if participant == "alice" {
			return "alice-principal"
		}
		return "owner-principal"
	}}
	fixture := &publicationTestFixture{db: db, ctx: ctx, job: job, attempt: attempt, observer: observer, exchange: exchange, state: state, manifest: manifest, intent: intent}
	if external {
		fixture.addExternal(t)
	}
	return fixture
}
func (f *publicationTestFixture) observe(t *testing.T) PublicationObservation {
	t.Helper()
	v, err := f.observer.Observe(f.ctx, f.job, f.attempt, "space")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Validate(); err != nil {
		t.Fatal(err)
	}
	return v
}
func (f *publicationTestFixture) update(t *testing.T, table, id string, values map[string]any) {
	t.Helper()
	if err := f.db.WithTx(f.ctx, true, func(tx *store.Tx) error { return tx.Update(f.ctx, table, map[string]any{"id": id}, values) }); err != nil {
		t.Fatal(err)
	}
}
func (f *publicationTestFixture) directive(t *testing.T, component string) map[string]any {
	t.Helper()
	attempt, err := f.db.One(f.ctx, "SELECT * FROM jm_attempts WHERE id = ?", "attempt")
	if err != nil {
		t.Fatal(err)
	}
	directives := publicationMap(publicationMap(attempt["details_json"])["reconciliation_directives"])
	items, ok := directives[component].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("directives=%#v", directives)
	}
	return publicationMap(items[0])
}
func (f *publicationTestFixture) addExternal(t *testing.T) {
	t.Helper()
	encoded := publicationTestBytes(t, []any{"alice"})
	f.component = "participant-" + publicationHash(encoded)[:40]
	details := map[string]any{"node_id": "external-node", "participant_id": "alice", "dataset_binding": "alice-local", "spec_digest": f.job["spec_hash"], "epoch": int64(1), "termination_confirmed": true, "termination_operation_id": "external-stop"}
	if err := f.db.WithTx(f.ctx, true, func(tx *store.Tx) error {
		return tx.Insert(f.ctx, "jm_provisioning_resources", map[string]any{"id": "external-receipt", "job_id": "job", "attempt_id": "attempt", "component_id": f.component, "kind": "external_execution", "external_id": "execution-key", "state": "ready", "retained": true, "ownership_json": map[string]any{"job_id": "job", "attempt_id": "attempt", "component_id": f.component}, "details_json": details})
	}); err != nil {
		t.Fatal(err)
	}
	delete(f.state.files, "initialization.json")
	f.state.files["progress.json"] = publicationTestBytes(t, map[string]any{"job_id": "job", "component_id": "owner", "phase": "completed"})
	global := map[string]any{"id": "global-target", "space_id": "space", "creator": "owner-principal", "kind": "model.global", "state": "published", "metadata": map[string]any{"hf2l_files": map[string]any{"fedavg_round.json": map[string]any{"round": int64(1)}}}}
	submission := map[string]any{"participant": "alice", "base_revision": "global-base", "round": int64(0), "num_examples": int64(8), "checkpoint_files_sha256": map[string]any{"weights.safetensors": strings.Repeat("b", 64)}}
	intent := map[string]any{"repo_id": "space", "participant": "alice", "base_revision": "global-base", "submission_revision": "client-output", "submitted_at": "2026-10-09T22:00:00Z", "checkpoint_files_sha256": map[string]any{"weights.safetensors": strings.Repeat("b", 64)}}
	client := map[string]any{"id": "client-record", "space_id": "space", "creator": "alice-principal", "creator_bindings": map[string]any{"participant": "alice"}, "kind": "training.update", "state": "published", "attachments": []any{map[string]any{"path": "weights.safetensors", "sha256": strings.Repeat("b", 64)}}, "metadata": map[string]any{"base_record_id": "global-base", "hf2l_files": map[string]any{"fedavg_submission.json": submission}}}
	directory := "listener/jobs/" + publicationHash([]byte("global-base")) + "/work"
	reader := &publicationTestState{files: map[string][]byte{
		"progress.json":       publicationTestBytes(t, map[string]any{"job_id": "job", "component_id": f.component, "epoch": int64(1), "phase": "failed"}),
		"listener/state.json": publicationTestBytes(t, map[string]any{"active": "global-base", "jobs": map[string]any{"global-base": map[string]any{"revision": "global-base", "status": "uncertain"}}}),
		directory + "/client-publication-intent.json":       publicationTestBytes(t, intent),
		directory + "/trained_model.exchange-upload.json":   publicationTestBytes(t, map[string]any{"record_id": "client-record", "key": "client-upload"}),
		directory + "/trained_model/fedavg_submission.json": publicationTestBytes(t, submission),
	}}
	f.external = reader
	f.observer.ExternalStateReader = reader
	f.exchange.mainID = "global-target"
	f.exchange.records["global-target"] = global
	f.exchange.records["client-record"] = client
}
func TestPublicationAcceptedLostAcknowledgement(t *testing.T) {
	f := publicationTestFixtureNew(t, false)
	got := f.observe(t)
	if !got.Known || got.Status != "confirmed" || got.CurrentRound == nil || *got.CurrentRound != 0 {
		t.Fatalf("%+v", got)
	}
	proof := f.directive(t, "owner")
	if proof["record_id"] != "record" || proof["action"] != "confirmed" || proof["revocation_operation_id"] != "revoke" || proof["termination_operation_id"] != "stop" {
		t.Fatalf("%#v", proof)
	}
	if publicationString(proof["intent_sha256"]) == "" {
		t.Fatal("missing immutable intent fingerprint")
	}
	for _, id := range f.state.identities {
		if id.JobID != "job" || id.AttemptID != "attempt" || id.ComponentID != "owner" || id.Epoch != 1 {
			t.Fatalf("foreign state read: %+v", id)
		}
	}
}
func TestPublicationExactDraftProvesAbsenceAfterFencing(t *testing.T) {
	f := publicationTestFixtureNew(t, false)
	f.exchange.mainID = ""
	f.exchange.records["record"]["state"] = "draft"
	got := f.observe(t)
	if !got.Known || got.Status != "absent" || f.directive(t, "owner")["action"] != "absent" {
		t.Fatalf("%+v", got)
	}
}
func TestPublicationRejectsForeignServerProof(t *testing.T) {
	for _, field := range []string{"creator", "space", "kind", "hash", "manifest", "missing_receipt", "missing_record"} {
		t.Run(field, func(t *testing.T) {
			f := publicationTestFixtureNew(t, false)
			record := f.exchange.records["record"]
			switch field {
			case "creator":
				record["creator"] = "foreign"
			case "space":
				record["space_id"] = "foreign"
			case "kind":
				record["kind"] = "training.update"
			case "hash":
				record["attachments"] = []any{map[string]any{"path": "weights.safetensors", "sha256": strings.Repeat("f", 64)}}
			case "manifest":
				record["metadata"] = map[string]any{"hf2l_files": map[string]any{"fedavg_round.json": map[string]any{"round": int64(0)}}}
			case "missing_receipt":
				f.state.files["initial-model.exchange-upload.json"] = publicationTestBytes(t, map[string]any{"key": "lost-create"})
			case "missing_record":
				f.state.files["initial-model.exchange-upload.json"] = publicationTestBytes(t, map[string]any{"record_id": "missing"})
			}
			if got := f.observe(t); got.Known || got.Status != "unknown" {
				t.Fatalf("%+v", got)
			}
		})
	}
}
func TestPublicationFencingBarrierBeforeAnyStateRead(t *testing.T) {
	for _, field := range []string{"revoked", "stopped"} {
		t.Run(field, func(t *testing.T) {
			f := publicationTestFixtureNew(t, false)
			if field == "revoked" {
				f.update(t, "jm_attempts", "attempt", map[string]any{"revocation_confirmed": false})
			} else {
				f.update(t, "jm_allocations", "allocation", map[string]any{"termination_confirmed": false})
			}
			if got := f.observe(t); got.Known {
				t.Fatalf("%+v", got)
			}
			if len(f.state.names) != 0 {
				t.Fatal("state read before positive fence")
			}
		})
	}
}
func TestPublicationStateFailuresRemainUnknown(t *testing.T) {
	for _, kind := range []string{"transport", "oversized", "missing_progress", "invalid_json", "foreign_identity"} {
		t.Run(kind, func(t *testing.T) {
			f := publicationTestFixtureNew(t, false)
			switch kind {
			case "transport":
				f.state.err = errors.New("secret transport diagnostic")
			case "oversized":
				f.state.oversize = true
			case "missing_progress":
				delete(f.state.files, "progress.json")
			case "invalid_json":
				f.state.files["progress.json"] = []byte("{")
			case "foreign_identity":
				f.state.files["progress.json"] = publicationTestBytes(t, map[string]any{"job_id": "foreign", "component_id": "owner"})
			}
			got := f.observe(t)
			if got.Known || strings.Contains(publicationString(got.Evidence["reason"]), "secret") {
				t.Fatalf("%+v", got)
			}
		})
	}
}
func TestPublicationBoundedStateRejectsUnsafeNamesBeforeTransport(t *testing.T) {
	for _, name := range []string{"../foreign", "/host/file", "a//b", "a/./b", "a\\b", "a\nfile", strings.Repeat("a", 4097)} {
		state := &publicationTestState{files: map[string][]byte{}}
		reader := &publicationBoundedState{reader: state}
		if _, err := reader.read(context.Background(), name); err == nil {
			t.Errorf("accepted %q", name)
		}
		if len(state.names) != 0 {
			t.Fatal("contacted transport for unsafe name")
		}
	}
	reader := &publicationBoundedState{reader: &publicationTestState{files: map[string][]byte{}}}
	for i := 0; i < 32; i++ {
		if _, err := reader.read(context.Background(), "missing.json"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := reader.read(context.Background(), "missing.json"); err == nil {
		t.Fatal("unbounded remote reads")
	}
	large := &publicationBoundedState{reader: PublicationStateReaderFunc(func(context.Context, executor.ExecutionIdentity, string, int64) ([]byte, error) {
		return make([]byte, 1024*1024), nil
	})}
	for i := 0; i < 16; i++ {
		if _, err := large.read(context.Background(), "large.json"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := large.read(context.Background(), "large.json"); err == nil {
		t.Fatal("unbounded aggregate state bytes")
	}
}
func TestPublicationNoStartIsDurableAbsence(t *testing.T) {
	f := publicationTestFixtureNew(t, false)
	if _, err := f.db.Exec(f.ctx, "DELETE FROM jm_provisioning_operations WHERE operation = ?", "start"); err != nil {
		t.Fatal(err)
	}
	got, err := f.observer.Observe(f.ctx, f.job, f.attempt, "")
	if err != nil || !got.Known || got.Status != "absent" || got.CurrentRound == nil || *got.CurrentRound != 0 {
		t.Fatalf("%+v %v", got, err)
	}
	if len(f.state.names) != 0 {
		t.Fatal("unstarted execution state unnecessarily read")
	}
}
func TestPublicationExternalExactReceiptProducesDirective(t *testing.T) {
	f := publicationTestFixtureNew(t, true)
	got := f.observe(t)
	if !got.Known || got.CurrentRound == nil || *got.CurrentRound != 1 {
		t.Fatalf("%+v", got)
	}
	proof := f.directive(t, f.component)
	if proof["role"] != "client" || proof["action"] != "confirmed" || proof["record_id"] != "client-record" || proof["termination_operation_id"] != "external-stop" {
		t.Fatalf("%#v", proof)
	}
	for _, id := range f.external.identities {
		if id.JobID != "job" || id.AttemptID != "attempt" || id.ComponentID != f.component || id.Epoch != 1 {
			t.Fatalf("%+v", id)
		}
	}
}
func TestPublicationExternalBarrierCannotBeReplacedByMain(t *testing.T) {
	for _, kind := range []string{"unstopped", "old_epoch", "bool_epoch", "foreign_spec", "foreign_participant", "foreign_dataset", "foreign_owner", "missing_stop", "missing_reader"} {
		t.Run(kind, func(t *testing.T) {
			f := publicationTestFixtureNew(t, true)
			resource, err := f.db.One(f.ctx, "SELECT * FROM jm_provisioning_resources WHERE id = ?", "external-receipt")
			if err != nil {
				t.Fatal(err)
			}
			details := publicationMap(resource["details_json"])
			owner := publicationMap(resource["ownership_json"])
			switch kind {
			case "unstopped":
				details["termination_confirmed"] = false
			case "old_epoch":
				details["epoch"] = int64(2)
			case "bool_epoch":
				details["epoch"] = true
			case "foreign_spec":
				details["spec_digest"] = strings.Repeat("f", 64)
			case "foreign_participant":
				details["participant_id"] = "bob"
			case "foreign_dataset":
				details["dataset_binding"] = "foreign"
			case "foreign_owner":
				owner["job_id"] = "foreign"
			case "missing_stop":
				details["termination_operation_id"] = nil
			case "missing_reader":
				f.observer.ExternalStateReader = nil
			}
			f.update(t, "jm_provisioning_resources", "external-receipt", map[string]any{"details_json": details, "ownership_json": owner})
			got := f.observe(t)
			if got.Known {
				t.Fatalf("%+v", got)
			}
			if kind != "missing_reader" && len(f.external.names) != 0 {
				t.Fatal("external state read before barrier")
			}
		})
	}
}
func TestPublicationExternalForeignSubmissionRejected(t *testing.T) {
	for _, field := range []string{"creator", "hash", "base", "participant", "missing_receipt"} {
		t.Run(field, func(t *testing.T) {
			f := publicationTestFixtureNew(t, true)
			record := f.exchange.records["client-record"]
			switch field {
			case "creator":
				record["creator"] = "foreign"
			case "hash":
				record["attachments"] = []any{map[string]any{"path": "weights.safetensors", "sha256": strings.Repeat("c", 64)}}
			case "base":
				publicationMap(record["metadata"])["base_record_id"] = "foreign-base"
			case "participant":
				record["creator_bindings"] = map[string]any{"participant": "bob"}
			case "missing_receipt":
				directory := "listener/jobs/" + publicationHash([]byte("global-base")) + "/work"
				f.external.files[directory+"/trained_model.exchange-upload.json"] = publicationTestBytes(t, map[string]any{"key": "lost"})
			}
			if got := f.observe(t); got.Known {
				t.Fatalf("%+v", got)
			}
		})
	}
}
func TestPublicationExplicitUserEvidenceRequiresMatchingServerProof(t *testing.T) {
	for _, valid := range []bool{true, false} {
		f := publicationTestFixtureNew(t, false)
		request := map[string]any{"publication_id": "record", "outcome": "published", "evidence_ref": "exchange:space:record"}
		if !valid {
			request["evidence_ref"] = "user-says-so"
		}
		f.update(t, "jm_attempts", "attempt", map[string]any{"details_json": map[string]any{"reconciliation_evidence": request}})
		got := f.observe(t)
		if got.Known != valid {
			t.Fatalf("valid=%v got=%+v", valid, got)
		}
	}
}
func TestPublicationOwnerAcquisitionAndReferenceProof(t *testing.T) {
	for _, mode := range []string{"confirmed", "acquisition_mismatch", "orphan", "completed_draft"} {
		t.Run(mode, func(t *testing.T) {
			f := publicationTestFixtureNew(t, false)
			delete(f.state.files, "initialization.json")
			manifest := map[string]any{"round": int64(1), "checkpoint_files_sha256": map[string]any{"weights.safetensors": strings.Repeat("a", 64)}}
			manifestBytes := publicationTestBytes(t, manifest)
			active := map[string]any{"revision": "base", "source_round": int64(0), "status": "uncertain", "publication_intent": map[string]any{"target_round": int64(1), "aggregate_dir": "/job/state/aggregate", "manifest_sha256": publicationHash(manifestBytes)}}
			f.state.files["listener/state.json"] = publicationTestBytes(t, map[string]any{"active": "base", "jobs": map[string]any{"base": active}})
			f.state.files["aggregate.exchange-upload.json"] = publicationTestBytes(t, map[string]any{"record_id": "record"})
			f.state.files["aggregate/fedavg_round.json"] = manifestBytes
			claimPath := "listener/jobs/" + publicationHash([]byte("base")) + "/claim-state.json"
			f.state.files[claimPath] = publicationTestBytes(t, map[string]any{"claim_id": "claim"})
			f.exchange.records["record"]["metadata"] = map[string]any{"hf2l_files": map[string]any{"fedavg_round.json": manifest}}
			f.exchange.acquisition = map[string]any{"state": "completed", "result_record_id": "record"}
			switch mode {
			case "acquisition_mismatch":
				f.exchange.acquisition["result_record_id"] = "foreign"
			case "orphan":
				f.exchange.mainID = "base-record"
				f.exchange.records["base-record"] = map[string]any{"id": "base-record", "kind": "model.global", "state": "published", "metadata": map[string]any{"hf2l_files": map[string]any{"fedavg_round.json": map[string]any{"round": int64(0)}}}}
				f.exchange.acquisition = map[string]any{"state": "acquired"}
			case "completed_draft":
				f.exchange.mainID = ""
				f.exchange.records["record"]["state"] = "draft"
			}
			got := f.observe(t)
			expected := mode == "confirmed" || mode == "orphan"
			if got.Known != expected {
				t.Fatalf("%+v", got)
			}
			if mode == "orphan" && f.directive(t, "owner")["action"] != "absent" {
				t.Fatal("orphan cannot count as reference commit")
			}
		})
	}
}
func TestPublicationAncestryRequiresContiguousPublishedGlobals(t *testing.T) {
	f := publicationTestFixtureNew(t, false)
	record := func(id, parent string, round int64) map[string]any {
		return map[string]any{"id": id, "kind": "model.global", "state": "published", "metadata": map[string]any{"base_record_id": parent, "hf2l_files": map[string]any{"fedavg_round.json": map[string]any{"round": round}}}}
	}
	base := record("base", "", 0)
	middle := record("middle", "base", 1)
	main := record("main", "middle", 2)
	f.exchange.records["base"] = base
	f.exchange.records["middle"] = middle
	if ok, err := f.observer.inChain(f.ctx, "space", "base", main); err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	publicationMap(publicationMap(middle["metadata"])["hf2l_files"])["fedavg_round.json"] = map[string]any{"round": int64(0)}
	if _, err := f.observer.inChain(f.ctx, "space", "base", main); err == nil {
		t.Fatal("accepted noncontiguous global ancestry")
	}
	f.observer.MaxAncestry = 1
	f.exchange.records["middle"] = record("middle", "base", 1)
	if _, err := f.observer.inChain(f.ctx, "space", "base", main); err == nil {
		t.Fatal("ignored ancestry bound")
	}
}
func TestPublicationFingerprintMutableInitializationFieldsExcluded(t *testing.T) {
	base := map[string]any{"binding": map[string]any{"job_id": "j"}, "manifest_sha256": strings.Repeat("a", 64), "checkpoint_files_sha256": map[string]any{"weights.safetensors": strings.Repeat("b", 64)}}
	before, err := PublicationIntentFingerprint("init", base)
	if err != nil {
		t.Fatal(err)
	}
	base["phase"] = "uncertain"
	base["error"] = "lost reply"
	base["result"] = "record"
	after, err := PublicationIntentFingerprint("init", base)
	if err != nil || before != after {
		t.Fatal("mutable result altered immutable intent")
	}
	base["manifest_sha256"] = strings.Repeat("c", 64)
	changed, _ := PublicationIntentFingerprint("init", base)
	if changed == before {
		t.Fatal("manifest hash did not bind intent")
	}
	for _, role := range []string{"init", "owner", "client", "invalid"} {
		if _, err := PublicationIntentFingerprint(role, map[string]any{}); err == nil {
			t.Errorf("accepted incomplete %s", role)
		}
	}
	_, err = PublicationIntentFingerprint("client", map[string]any{"repo_id": "space", "participant": "alice", "base_revision": "base", "submission_revision": "output", "submitted_at": "now", "checkpoint_files_sha256": map[string]any{}, "large": strings.Repeat("x", 1024*1024)})
	if err == nil {
		t.Fatal("accepted oversized intent")
	}
}

// These hashes were independently generated from the reference Python
// publication_intent_fingerprint algorithm, including Unicode and float types.
func TestPublicationFingerprintPythonGoldenVectors(t *testing.T) {
	cases := []struct{ role, document, sha string }{
		{"init", `{"binding":{"float":1.0,"name":"é<>&😀","negative_zero":-0.0,"small":1e-07},"checkpoint_files_sha256":{"x.safetensors":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"manifest_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","phase":"uncertain"}`, "f2617ce94d2c4875a0194588a587e0ae5b19fd50a4b1515bcd2f9c2c70ee513d"},
		{"owner", `{"publication_intent":{"aggregate_dir":"/job/state/aggregate","description":"é<>&😀","target_round":1,"value":1.0},"revision":"global-base","source_round":0,"status":"uncertain"}`, "01a7fad44b045257ff19aafc28958da6ab072c13078fe44323f30a9522b342c2"},
		{"client", `{"base_revision":"base","checkpoint_files_sha256":{"weights.safetensors":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"meta":{"description":"é<>&😀","float":1.0,"small":1e-07},"participant":"alice","repo_id":"space","submission_revision":"output","submitted_at":"2026-10-09T22:00:00Z"}`, "ee4b753b700f6f2d4615b6f2b2db5593c554c2bf799052b36cb720b9c956d5c0"},
	}
	for _, item := range cases {
		t.Run(item.role, func(t *testing.T) {
			document, err := publicationDecode([]byte(item.document))
			if err != nil {
				t.Fatal(err)
			}
			actual, err := PublicationIntentFingerprint(item.role, document)
			if err != nil || actual != item.sha {
				t.Fatalf("hash=%s expected=%s err=%v", actual, item.sha, err)
			}
		})
	}
}

func TestPublicationMalformedDurableStateCannotAuthorizeRecovery(t *testing.T) {
	for _, kind := range []string{"initial_phase", "listener_active", "listener_jobs", "listener_job", "listener_status", "requested_evidence", "external_stop_receipt"} {
		t.Run(kind, func(t *testing.T) {
			f := publicationTestFixtureNew(t, kind == "external_stop_receipt")
			switch kind {
			case "initial_phase":
				f.intent["phase"] = map[string]any{"publishing": true}
				f.state.files["initialization.json"] = publicationTestBytes(t, f.intent)
			case "listener_active", "listener_jobs", "listener_job", "listener_status":
				delete(f.state.files, "initialization.json")
				f.state.files["progress.json"] = publicationTestBytes(t, map[string]any{"job_id": "job", "component_id": "owner", "phase": "failed"})
				listener := map[string]any{"active": "base", "jobs": map[string]any{"base": map[string]any{"status": "uncertain", "revision": "base"}}}
				switch kind {
				case "listener_active":
					listener["active"] = []any{"base"}
				case "listener_jobs":
					listener["jobs"] = []any{"bad"}
				case "listener_job":
					listener["jobs"] = map[string]any{"base": []any{"bad"}}
				case "listener_status":
					listener["jobs"] = map[string]any{"base": map[string]any{"status": map[string]any{"uncertain": true}}}
				}
				f.state.files["listener/state.json"] = publicationTestBytes(t, listener)
			case "requested_evidence":
				f.update(t, "jm_attempts", "attempt", map[string]any{"details_json": map[string]any{"reconciliation_evidence": []any{"unverified"}}})
			case "external_stop_receipt":
				resource, err := f.db.One(f.ctx, "SELECT * FROM jm_provisioning_resources WHERE id = ?", "external-receipt")
				if err != nil {
					t.Fatal(err)
				}
				details := publicationMap(resource["details_json"])
				details["stop_receipt"] = nil
				f.update(t, "jm_provisioning_resources", "external-receipt", map[string]any{"details_json": details})
			}
			if got := f.observe(t); got.Known {
				t.Fatalf("malformed %s authorized recovery: %+v", kind, got)
			}
		})
	}
}
