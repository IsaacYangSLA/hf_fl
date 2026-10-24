package service

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/store"
)

func newManagedFixture(t *testing.T) (*Service, domain.Principal, string) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, "sqlite:///"+filepath.Join(t.TempDir(), "exchange.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = store.Initialize(ctx, db); err != nil {
		t.Fatal(err)
	}
	owner := domain.Principal{ID: domain.PrincipalID("https://identity.example", "owner"), Subject: "owner", BootstrapAdmin: true}
	service := New(db, Options{Auth: AuthOptions{
		AdminSubject: "owner", WorkloadIssuer: "https://workload.example",
		ProvisioningPrincipalIDs: []string{owner.ID},
	}})
	space, err := service.CreateSpace(ctx, owner, Object{"name": "Managed integration"}, "managed-create")
	if err != nil {
		t.Fatal(err)
	}
	sid := str(space["id"])
	if _, err = service.EnableManagedSpace(ctx, owner, sid, Object{"job_id": "job-a"}, "enable"); err != nil {
		t.Fatal(err)
	}
	return service, owner, sid
}

func managedError(t *testing.T, err error, want string) {
	t.Helper()
	var typed *domain.Error
	if !errors.As(err, &typed) || typed.Code != want {
		t.Fatalf("got %T %v, want error %s", err, err, want)
	}
}

func managedNow(t *testing.T, s *Service) float64 {
	t.Helper()
	now, err := s.DB.Now(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return now
}

func managedGrantBody(t *testing.T, s *Service, owner domain.Principal, sid, subject string) (Object, string) {
	t.Helper()
	pid := domain.PrincipalID(s.Settings.Auth.WorkloadIssuer, subject)
	if _, err := s.PutMember(context.Background(), owner, sid, pid, Object{
		"subject": subject, "roles": []string{"admin", "contributor", "reader"},
		"bindings": Object{"participant": "alice"},
	}); err != nil {
		t.Fatal(err)
	}
	return Object{
		"subject": subject, "job_id": "job-a", "attempt_id": "attempt-one", "component_id": "alice",
		"epoch": int64(1), "roles": []string{"contributor"}, "bindings": Object{"participant": "alice"},
		"certificate_thumbprint": strings.Repeat("a", 43), "expires_at": managedNow(t, s) + 3600,
	}, pid
}

func managedPrincipal(body, grant Object, pid, sid string, now float64) domain.Principal {
	return domain.Principal{ID: pid, Subject: str(body["subject"]), Workload: &domain.WorkloadIdentity{
		GrantID: str(grant["grant_id"]), SpaceID: sid, JobID: str(body["job_id"]),
		AttemptID: str(body["attempt_id"]), ComponentID: str(body["component_id"]), Epoch: num(body["epoch"]),
		CertificateThumbprint: str(body["certificate_thumbprint"]), ExpiresAt: now + 60,
	}}
}

func TestManagedGrantStateMachine(t *testing.T) {
	ctx := context.Background()
	s, owner, sid := newManagedFixture(t)
	body, pid := managedGrantBody(t, s, owner, sid, "alice")
	grant, err := s.CreateWorkloadGrant(ctx, owner, sid, body, "grant-one")
	if err != nil {
		t.Fatal(err)
	}
	expectedID, err := domain.Hash([]any{sid, owner.ID, "grant-one"})
	if err != nil || grant["grant_id"] != expectedID {
		t.Fatalf("grant identity mismatch: %v %v", grant, err)
	}
	replayed, err := s.CreateWorkloadGrant(ctx, owner, sid, body, "grant-one")
	if err != nil || !equal(replayed, grant) {
		t.Fatalf("idempotent grant mismatch: %v", err)
	}
	workload := managedPrincipal(body, grant, pid, sid, managedNow(t, s))
	verified, err := s.VerifyWorkloadGrant(ctx, workload, sid)
	if err != nil || !equal(verified["effective_roles"], []string{"contributor"}) {
		t.Fatalf("effective grant ceiling failed: %v %v", verified, err)
	}
	storedMember, err := s.DB.One(ctx, "SELECT roles FROM v2_members WHERE space_id=? AND principal_id=?", sid, pid)
	if err != nil || !managedContains(stringsOf(storedMember["roles"]), "admin") {
		t.Fatalf("grant ceiling modified persisted membership: %v %v", storedMember, err)
	}
	_, err = s.GetManagedSpace(ctx, workload, sid)
	managedError(t, err, "role_required")
	_, err = s.CreateWorkloadGrant(ctx, workload, sid, body, "not-provisioner")
	managedError(t, err, "provisioning_principal_required")
	_, err = s.RetireManagedSpace(ctx, owner, sid, Object{"job_id": "job-a"}, "retire-active")
	managedError(t, err, "workload_revocation_required")

	for name, mutate := range map[string]func(*domain.Principal){
		"subject":       func(p *domain.Principal) { p.Subject = "other" },
		"principal":     func(p *domain.Principal) { p.ID = owner.ID },
		"job":           func(p *domain.Principal) { p.Workload.JobID = "foreign" },
		"attempt":       func(p *domain.Principal) { p.Workload.AttemptID = "foreign" },
		"component":     func(p *domain.Principal) { p.Workload.ComponentID = "foreign" },
		"epoch":         func(p *domain.Principal) { p.Workload.Epoch++ },
		"certificate":   func(p *domain.Principal) { p.Workload.CertificateThumbprint = strings.Repeat("b", 43) },
		"expired token": func(p *domain.Principal) { p.Workload.ExpiresAt = 1 },
		"missing grant": func(p *domain.Principal) { p.Workload.GrantID = "missing" },
	} {
		t.Run(name, func(t *testing.T) {
			copyPrincipal := workload
			copyIdentity := *workload.Workload
			copyPrincipal.Workload = &copyIdentity
			mutate(&copyPrincipal)
			_, err := s.VerifyWorkloadGrant(ctx, copyPrincipal, sid)
			managedError(t, err, "workload_grant_invalid")
		})
	}
	foreign := workload
	identity := *workload.Workload
	foreign.Workload = &identity
	foreign.Workload.SpaceID = "foreign"
	_, err = s.VerifyWorkloadGrant(ctx, foreign, sid)
	managedError(t, err, "space_not_found")

	// An expired grant is still an execution owner; expiry cannot authorize takeover.
	if err = s.DB.Update(ctx, "v2_workload_grants", Object{"id": grant["grant_id"]}, Object{"expires_at": managedNow(t, s) - 1}); err != nil {
		t.Fatal(err)
	}
	_, err = s.VerifyWorkloadGrant(ctx, workload, sid)
	managedError(t, err, "workload_grant_invalid")
	second := clone(body)
	second["attempt_id"], second["epoch"] = "attempt-two", int64(2)
	_, err = s.CreateWorkloadGrant(ctx, owner, sid, second, "premature-takeover")
	managedError(t, err, "previous_attempt_not_revoked")

	revoked, err := s.RevokeWorkloadGrants(ctx, owner, sid, Object{"attempt_id": "attempt-one"}, "revoke-one")
	if err != nil || num(revoked["revoked"]) != 1 {
		t.Fatalf("revoke failed: %v %v", revoked, err)
	}
	_, err = s.CreateWorkloadGrant(ctx, owner, sid, body, "resurrect-old")
	managedError(t, err, "attempt_already_revoked")
	tooOld := clone(second)
	tooOld["epoch"] = int64(1)
	_, err = s.CreateWorkloadGrant(ctx, owner, sid, tooOld, "old-epoch")
	managedError(t, err, "stale_workload_epoch")
	secondGrant, err := s.CreateWorkloadGrant(ctx, owner, sid, second, "grant-two")
	if err != nil {
		t.Fatal(err)
	}
	replayedRevocation, err := s.RevokeWorkloadGrants(ctx, owner, sid, Object{"attempt_id": "attempt-one"}, "revoke-one")
	if err != nil || !equal(replayedRevocation, revoked) {
		t.Fatalf("revocation replay changed: %v %v", replayedRevocation, err)
	}
	secondPrincipal := managedPrincipal(second, secondGrant, pid, sid, managedNow(t, s))
	if _, err = s.VerifyWorkloadGrant(ctx, secondPrincipal, sid); err != nil {
		t.Fatalf("old revocation replay fenced successor: %v", err)
	}
	changedComponent := clone(second)
	changedComponent["component_id"] = "bob"
	_, err = s.CreateWorkloadGrant(ctx, owner, sid, changedComponent, "component-change")
	managedError(t, err, "workload_component_immutable")
	_, err = s.VerifyWorkloadGrant(ctx, workload, sid)
	managedError(t, err, "workload_grant_invalid")
	_, err = s.GetWorkloadGrant(ctx, owner, sid, str(secondGrant["grant_id"]))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.RevokeWorkloadGrants(ctx, owner, sid, Object{"attempt_id": "attempt-two"}, "revoke-two"); err != nil {
		t.Fatal(err)
	}
	retired, err := s.RetireManagedSpace(ctx, owner, sid, Object{"job_id": "job-a"}, "retire-final")
	if err != nil || retired["status"] != "retired" || retired["cleanup_pending"] != false || retired["provenance_retained"] != true {
		t.Fatalf("retirement failed: %v %v", retired, err)
	}
	_, err = s.PutMember(ctx, owner, sid, "other", Object{"roles": []string{"reader"}})
	managedError(t, err, "managed_space_retired")
	if _, err = s.RevokeWorkloadGrants(ctx, owner, sid, Object{"attempt_id": "never-created"}, "future-tombstone"); err != nil {
		t.Fatal(err)
	}
	visible, err := s.GetManagedSpace(ctx, owner, sid)
	if err != nil || visible["status"] != "retired" {
		t.Fatalf("retired history inaccessible: %v", err)
	}
}

func TestManagedPrincipalBoundaries(t *testing.T) {
	ctx := context.Background()
	s, owner, sid := newManagedFixture(t)
	broker := domain.Principal{ID: domain.PrincipalID("https://identity.example", "broker"), Subject: "broker"}
	ordinary := domain.Principal{ID: domain.PrincipalID("https://identity.example", "ordinary"), Subject: "ordinary", BootstrapAdmin: true}
	s.Settings.Auth.DownloadBrokerPrincipalIDs = []string{broker.ID}
	for _, principal := range []domain.Principal{broker, ordinary} {
		if _, err := s.PutMember(ctx, owner, sid, principal.ID, Object{"subject": principal.Subject, "roles": allRoles}); err != nil {
			t.Fatal(err)
		}
	}
	membership, err := s.GetMembership(ctx, broker, sid)
	if err != nil || !equal(membership["roles"], []string{"reader"}) {
		t.Fatalf("download broker ceiling failed: %v %v", membership, err)
	}
	_, err = s.PutMember(ctx, broker, sid, "other", Object{"roles": []string{"reader"}})
	managedError(t, err, "role_required")
	_, err = s.GetSpace(ctx, ordinary, sid)
	managedError(t, err, "space_not_found")
	_, err = s.GetManagedSpace(ctx, ordinary, sid)
	managedError(t, err, "space_not_found")
	_, err = s.EnableManagedSpace(ctx, ordinary, sid, Object{"job_id": "job-a"}, "unauthorized")
	managedError(t, err, "provisioning_principal_required")
	_, err = s.VerifyWorkloadGrant(ctx, owner, sid)
	managedError(t, err, "workload_required")

	_, err = s.EnableManagedSpace(ctx, owner, sid, Object{"job_id": "changed"}, "change-binding")
	managedError(t, err, "managed_space_binding_immutable")
	_, err = s.EnableManagedSpace(ctx, owner, sid, Object{"job_id": "changed"}, "enable")
	managedError(t, err, "idempotency_conflict")
	other, err := s.CreateSpace(ctx, owner, Object{"name": "Other"}, "other-space")
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.EnableManagedSpace(ctx, owner, str(other["id"]), Object{"job_id": "job-a"}, "foreign-job")
	managedError(t, err, "managed_job_space_conflict")
	managed, err := s.IsManagedSpace(ctx, sid)
	if err != nil || !managed {
		t.Fatalf("managed existence: %v", err)
	}
	managed, err = s.IsManagedSpace(ctx, str(other["id"]))
	if err != nil || managed {
		t.Fatalf("ordinary space incorrectly managed: %v", err)
	}
	_, err = s.GetManagedSpace(ctx, owner, str(other["id"]))
	managedError(t, err, "managed_space_not_found")
}

func TestManagedGrantStrictValidation(t *testing.T) {
	ctx := context.Background()
	s, owner, sid := newManagedFixture(t)
	body, _ := managedGrantBody(t, s, owner, sid, "alice")
	cases := []struct {
		name, field, code string
		value             any
	}{
		{"missing subject", "subject", "invalid_workload_binding", nil},
		{"long subject", "subject", "invalid_workload_binding", strings.Repeat("a", 257)},
		{"numeric job", "job_id", "invalid_workload_binding", 1},
		{"long attempt", "attempt_id", "invalid_workload_binding", strings.Repeat("a", 129)},
		{"blank component", "component_id", "invalid_workload_binding", ""},
		{"boolean epoch", "epoch", "invalid_workload_epoch", true},
		{"float epoch", "epoch", "invalid_workload_epoch", 1.0},
		{"float lexeme epoch", "epoch", "invalid_workload_epoch", json.Number("1.0")},
		{"zero epoch", "epoch", "invalid_workload_epoch", int64(0)},
		{"overflow epoch", "epoch", "invalid_workload_epoch", json.Number("9223372036854775808")},
		{"short certificate", "certificate_thumbprint", "invalid_certificate_thumbprint", strings.Repeat("a", 42)},
		{"invalid certificate alphabet", "certificate_thumbprint", "invalid_certificate_thumbprint", strings.Repeat("+", 43)},
		{"nil roles", "roles", "invalid_roles", nil},
		{"no roles", "roles", "invalid_roles", []string{}},
		{"wrong role", "roles", "invalid_roles", []string{"superuser"}},
		{"typed role", "roles", "invalid_roles", []any{true}},
		{"null bindings", "bindings", "invalid_bindings", nil},
		{"list bindings", "bindings", "invalid_bindings", []any{}},
		{"boolean expiry", "expires_at", "invalid_grant_expiry", true},
		{"text expiry", "expires_at", "invalid_grant_expiry", "9999999999"},
		{"NaN expiry", "expires_at", "invalid_grant_expiry", math.NaN()},
		{"infinite expiry", "expires_at", "invalid_grant_expiry", math.Inf(1)},
		{"expired grant", "expires_at", "invalid_grant_expiry", 1},
		{"too long grant", "expires_at", "invalid_grant_expiry", managedNow(t, s) + 31*86400},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			changed := clone(body)
			changed[test.field] = test.value
			_, err := s.CreateWorkloadGrant(ctx, owner, sid, changed, test.name)
			managedError(t, err, test.code)
		})
	}
	// Python string-length limits count Unicode code points, not UTF-8 bytes.
	unicodeSubject := strings.Repeat("é", 256)
	unicodeBody, _ := managedGrantBody(t, s, owner, sid, unicodeSubject)
	if _, err := s.CreateWorkloadGrant(ctx, owner, sid, unicodeBody, "unicode-subject"); err != nil {
		t.Fatalf("valid Unicode subject rejected: %v", err)
	}
}

func TestManagedRetirementRetainsPhysicalChargesAndMarkers(t *testing.T) {
	ctx := context.Background()
	s, owner, sid := newManagedFixture(t)
	revision, err := s.RegisterType(ctx, owner, sid, "checkpoint", Object{"schema": Object{"type": "object"}}, "type")
	if err != nil {
		t.Fatal(err)
	}
	record, err := s.CreateRecord(ctx, owner, sid, Object{
		"kind": "checkpoint", "schema_revision_id": revision["id"], "metadata": Object{},
		"attachments": []any{Object{"path": "model.bin", "size": int64(10), "sha256": strings.Repeat("a", 64)}},
	}, "record")
	if err != nil {
		t.Fatal(err)
	}
	blob, err := s.DB.One(ctx, "SELECT id FROM v2_blobs WHERE record_id=?", record["id"])
	if err != nil || blob == nil {
		t.Fatalf("record attachment missing: %v", err)
	}
	blobID := str(blob["id"])
	now := managedNow(t, s)
	if err = s.DB.Insert(ctx, "v2_transfer_attempts", Object{
		"id": "attempt-physical", "blob_id": blobID, "object_key": "private/owned/object",
		"state": "uploading", "mutation_tokens": []string{"durable-inflight-put"}, "grant_expires_at": now + 300,
	}); err != nil {
		t.Fatal(err)
	}
	if err = s.DB.Update(ctx, "v2_blobs", Object{"id": blobID}, Object{"grant_expires_at": now + 300}); err != nil {
		t.Fatal(err)
	}
	retired, err := s.RetireManagedSpace(ctx, owner, sid, Object{"job_id": "job-a"}, "retire-with-data")
	if err != nil || retired["cleanup_pending"] != true {
		t.Fatalf("retirement released outstanding data: %v %v", retired, err)
	}
	space, err := s.DB.One(ctx, "SELECT allocated,reclaiming FROM v2_spaces WHERE id=?", sid)
	if err != nil || num(space["allocated"]) != 0 || num(space["reclaiming"]) != 10 {
		t.Fatalf("physical accounting lost: %v %v", space, err)
	}
	attempt, err := s.DB.One(ctx, "SELECT * FROM v2_transfer_attempts WHERE id=?", "attempt-physical")
	if err != nil || attempt["state"] != "cleanup" || !mutationTokensPending(attempt["mutation_tokens"]) || decimal(attempt["next_attempt"]) < now+299 {
		t.Fatalf("cleanup fence lost: %v %v", attempt, err)
	}
	// Even a cleaned blob does not make an outstanding mutation disappear.
	if err = s.DB.Update(ctx, "v2_blobs", Object{"id": blobID}, Object{"state": "cleaned"}); err != nil {
		t.Fatal(err)
	}
	state, err := s.GetManagedSpace(ctx, owner, sid)
	if err != nil || state["cleanup_pending"] != true {
		t.Fatalf("mutation marker not retained: %v %v", state, err)
	}
	if err = s.DB.Update(ctx, "v2_transfer_attempts", Object{"id": "attempt-physical"}, Object{"mutation_tokens": Object{}}); err != nil {
		t.Fatal(err)
	}
	state, err = s.GetManagedSpace(ctx, owner, sid)
	if err != nil || state["cleanup_pending"] != true {
		t.Fatalf("malformed marker was accepted as quiescence: %v %v", state, err)
	}
	if err = s.DB.Update(ctx, "v2_transfer_attempts", Object{"id": "attempt-physical"}, Object{"mutation_tokens": []string{}}); err != nil {
		t.Fatal(err)
	}
	state, err = s.GetManagedSpace(ctx, owner, sid)
	if err != nil || state["cleanup_pending"] != false {
		t.Fatalf("settled clean state not visible: %v %v", state, err)
	}
}

func TestManagedBindingEqualityMatchesPython(t *testing.T) {
	ctx := context.Background()
	s, owner, sid := newManagedFixture(t)
	body, pid := managedGrantBody(t, s, owner, sid, "alice")
	body["bindings"] = Object{"numeric": int64(1)}
	if _, err := s.PutMember(ctx, owner, sid, pid, Object{"roles": []string{"contributor"}, "bindings": Object{"numeric": 1.0}}); err != nil {
		t.Fatal(err)
	}
	grant, err := s.CreateWorkloadGrant(ctx, owner, sid, body, "numeric-binding")
	if err != nil {
		t.Fatal(err)
	}
	principal := managedPrincipal(body, grant, pid, sid, managedNow(t, s))
	if _, err = s.VerifyWorkloadGrant(ctx, principal, sid); err != nil {
		t.Fatalf("Python-equal numeric binding rejected: %v", err)
	}
}

func managedPostgresFixture(t *testing.T) (*Service, domain.Principal, string) {
	t.Helper()
	dsn := os.Getenv("HF2L_GO_EXCHANGE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set HF2L_GO_EXCHANGE_TEST_DATABASE_URL for owned PostgreSQL tests")
	}
	ctx := context.Background()
	admin, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schemaName := "go_managed_" + domain.NewID()
	if _, err = admin.Exec(ctx, `CREATE SCHEMA "`+schemaName+`"`); err != nil {
		_ = admin.Close()
		t.Fatal(err)
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schemaName)
	parsed.RawQuery = query.Encode()
	db, err := store.Open(ctx, parsed.String())
	if err != nil {
		_, _ = admin.Exec(ctx, `DROP SCHEMA "`+schemaName+`" CASCADE`)
		_ = admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		_, dropError := admin.Exec(context.Background(), `DROP SCHEMA "`+schemaName+`" CASCADE`)
		_ = admin.Close()
		if dropError != nil {
			t.Error("owned managed test schema cleanup failed")
		}
	})
	if err = store.Initialize(ctx, db); err != nil {
		t.Fatal(err)
	}
	owner := domain.Principal{ID: domain.PrincipalID("https://identity.example", "owner"), Subject: "owner", BootstrapAdmin: true}
	s := New(db, Options{Auth: AuthOptions{
		AdminSubject: "owner", WorkloadIssuer: "https://workload.example",
		ProvisioningPrincipalIDs: []string{owner.ID},
	}})
	space, err := s.CreateSpace(ctx, owner, Object{"name": "Managed PG"}, "managed-create")
	if err != nil {
		t.Fatal(err)
	}
	sid := str(space["id"])
	if _, err = s.EnableManagedSpace(ctx, owner, sid, Object{"job_id": "job-a"}, "enable"); err != nil {
		t.Fatal(err)
	}
	return s, owner, sid
}

func TestManagedPostgresCrossSpaceJobUniqueness(t *testing.T) {
	ctx := context.Background()
	s, owner, _ := managedPostgresFixture(t)
	var spaces []string
	for _, label := range []string{"first", "second"} {
		space, err := s.CreateSpace(ctx, owner, Object{"name": label}, label)
		if err != nil {
			t.Fatal(err)
		}
		spaces = append(spaces, str(space["id"]))
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for i, sid := range spaces {
		go func(i int, sid string) {
			<-start
			_, err := s.EnableManagedSpace(ctx, owner, sid, Object{"job_id": "job-race"}, "bind-"+strconv.Itoa(i))
			results <- err
		}(i, sid)
	}
	close(start)
	successes := 0
	for range spaces {
		err := <-results
		if err == nil {
			successes++
			continue
		}
		var typed *domain.Error
		var state interface{ SQLState() string }
		if !(errors.As(err, &typed) && typed.Code == "managed_job_space_conflict") &&
			!(errors.As(err, &state) && state.SQLState() == "23505") {
			t.Fatalf("unexpected concurrent binding failure: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent job binding admitted %d spaces", successes)
	}
	rows, err := s.DB.All(ctx, "SELECT space_id FROM v2_managed_spaces WHERE job_id=?", "job-race")
	if err != nil || len(rows) != 1 {
		t.Fatalf("managed job uniqueness lost: rows=%d err=%v", len(rows), err)
	}
}

func TestManagedPostgresGrantRevocationAndEpochFencing(t *testing.T) {
	ctx := context.Background()
	s, owner, sid := managedPostgresFixture(t)
	body, pid := managedGrantBody(t, s, owner, sid, "alice")
	oldGrant, err := s.CreateWorkloadGrant(ctx, owner, sid, body, "old")
	if err != nil {
		t.Fatal(err)
	}
	oldPrincipal := managedPrincipal(body, oldGrant, pid, sid, managedNow(t, s))
	next := clone(body)
	next["attempt_id"], next["epoch"] = "next", int64(2)
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		_, e := s.CreateWorkloadGrant(ctx, owner, sid, next, "next")
		results <- e
	}()
	go func() {
		<-start
		_, e := s.RevokeWorkloadGrants(ctx, owner, sid, Object{"attempt_id": "attempt-one"}, "revoke")
		results <- e
	}()
	close(start)
	for range 2 {
		e := <-results
		if e != nil {
			managedError(t, e, "previous_attempt_not_revoked")
		}
	}
	_, err = s.VerifyWorkloadGrant(ctx, oldPrincipal, sid)
	managedError(t, err, "workload_grant_invalid")
	if _, err = s.CreateWorkloadGrant(ctx, owner, sid, next, "next"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RevokeWorkloadGrants(ctx, owner, sid, Object{"attempt_id": "next"}, "revoke-next"); err != nil {
		t.Fatal(err)
	}

	// Two successor attempts cannot both remain enabled, even at different epochs.
	start = make(chan struct{})
	results = make(chan error, 2)
	for index := range 2 {
		go func(index int) {
			candidate := clone(body)
			candidate["attempt_id"] = "successor-" + strconv.Itoa(index)
			candidate["epoch"] = int64(3 + index)
			<-start
			_, e := s.CreateWorkloadGrant(ctx, owner, sid, candidate, "successor-"+strconv.Itoa(index))
			results <- e
		}(index)
	}
	close(start)
	successes := 0
	for range 2 {
		e := <-results
		if e == nil {
			successes++
			continue
		}
		var typed *domain.Error
		if !errors.As(e, &typed) || (typed.Code != "previous_attempt_not_revoked" && typed.Code != "stale_workload_epoch") {
			t.Fatalf("unexpected concurrent successor failure: %v", e)
		}
	}
	if successes != 1 {
		t.Fatalf("successor fencing admitted %d attempts", successes)
	}
	rows, err := s.DB.All(ctx, "SELECT id FROM v2_workload_grants WHERE space_id=? AND principal_id=? AND enabled=?", sid, pid, true)
	if err != nil || len(rows) != 1 {
		t.Fatalf("enabled execution ownership count=%d err=%v", len(rows), err)
	}
}
