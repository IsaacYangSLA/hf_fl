package manager

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func studyAdmin(t *testing.T, f *mgrFixture) {
	t.Helper()
	e := f.db.WithTx(context.Background(), true, func(tx *store.Tx) error {
		return tx.Update(context.Background(), "jm_project_members", Object{"project_id": "research", "principal_id": "owner"}, Object{"role": "admin"})
	})
	if e != nil {
		t.Fatal(e)
	}
}
func openStudy(t *testing.T, f *mgrFixture) Object {
	t.Helper()
	studyAdmin(t, f)
	v, e := f.m.PutStudySettings(context.Background(), "owner", "research", "A study for independent organizations", true, 1, "enable-study")
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func applyStudy(t *testing.T, f *mgrFixture, actor, pid string) Object {
	t.Helper()
	v, e := f.m.ApplyToStudy(context.Background(), actor, "research", pid, "My local data remain private", "apply-"+actor)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func approveStudy(t *testing.T, f *mgrFixture, app Object) Object {
	t.Helper()
	v, e := f.m.ReviewStudyApplication(context.Background(), "owner", "research", text(app["id"]), "approve", "Reviewed identity and project agreement", number(app["version"]), "approve-"+text(app["id"]))
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func managedStudySpec() domain.JobSpec {
	s := mgrSpec()
	for i := range s.Participants {
		s.Participants[i].Mode = "managed"
		componentID := s.Participants[i].ParticipantID + "-client"
		participantID := s.Participants[i].ParticipantID
		s.Participants[i].ComponentID = &componentID
		s.Components = append(s.Components, domain.ComponentSpec{ComponentID: componentID, Role: "participant", ParticipantID: &participantID, Resources: s.Components[0].Resources})
	}
	return s
}
func TestStudySelfApplicationApprovalDoesNotGrantOtherRoles(t *testing.T) {
	f := newMgrFixture(t)
	ctx := context.Background()
	_, e := f.m.GetStudy(ctx, "human-alice", "research")
	mgrError(t, e, 404, "study_not_found")
	open := openStudy(t, f)
	if open["registration_enabled"] != true || open["version"] != int64(2) {
		t.Fatal(open)
	}
	page, e := f.m.ListStudies(ctx, "human-alice", 50, "")
	if e != nil || len(arr(page["items"])) != 1 {
		t.Fatal(page, e)
	}
	alice := applyStudy(t, f, "human-alice", "alice")
	bob := applyStudy(t, f, "human-bob", "bob")
	if alice["principal_id"] != "human-alice" || alice["status"] != "pending" {
		t.Fatal(alice)
	}
	_, e = f.m.CreateJob(ctx, "owner", mgrSpec(), "pending-external")
	mgrError(t, e, 403, "study_participant_not_approved")
	_, e = f.m.CreateJob(ctx, "owner", managedStudySpec(), "pending-managed")
	mgrError(t, e, 403, "study_participant_not_approved")
	_, e = f.m.ReviewStudyApplication(ctx, "human-alice", "research", text(alice["id"]), "approve", "", 1, "self-approve")
	mgrError(t, e, 403, "project_admin_required")
	approved := approveStudy(t, f, alice)
	if approved["status"] != "approved" || approved["principal_id"] != "human-alice" {
		t.Fatal(approved)
	}
	_, e = f.m.CreateJob(ctx, "owner", mgrSpec(), "bob-pending")
	mgrError(t, e, 403, "study_participant_not_approved")
	approveStudy(t, f, bob)
	for label, spec := range map[string]domain.JobSpec{"external": mgrSpec(), "managed": managedStudySpec()} {
		job, e := f.m.CreateJob(ctx, "owner", spec, "approved-"+label)
		if e != nil {
			t.Fatal(label, e)
		}
		_, e = f.m.GetJob(ctx, "human-alice", text(job["id"]))
		mgrError(t, e, 404, "job_not_found")
	}
	catalog, e := f.m.Catalog(ctx, "human-alice")
	if e != nil || len(arr(catalog["projects"])) != 0 {
		t.Fatal(catalog, e)
	}
	_, e = f.m.CreateJob(ctx, "human-alice", mgrSpec(), "must-not-submit")
	mgrError(t, e, 403, "project_submitter_required")
	row, e := f.db.One(ctx, "SELECT COUNT(*) AS n FROM jm_project_members WHERE principal_id=?", "human-alice")
	if e != nil || number(row["n"]) != 0 {
		t.Fatal(row, e)
	}
	principal, e := f.m.DB.One(ctx, "SELECT principal_id FROM jm_study_applications WHERE project_id=? AND participant_id=? AND status='approved'", "research", "alice")
	if e != nil || principal["principal_id"] != "human-alice" {
		t.Fatal(principal, e)
	}
}
func TestStudyPolicyClosureIsStickyAndApprovedBindingImmutable(t *testing.T) {
	f := newMgrFixture(t)
	ctx := context.Background()
	opened := openStudy(t, f)
	alice := applyStudy(t, f, "human-alice", "alice")
	approveStudy(t, f, alice)
	closed, e := f.m.PutStudySettings(ctx, "owner", "research", "Closed to new applicants", false, number(opened["version"]), "close")
	if e != nil || closed["registration_enabled"] != true || closed["registration_open"] != false {
		t.Fatal(closed, e)
	}
	_, e = f.m.GetStudy(ctx, "outsider", "research")
	mgrError(t, e, 404, "study_not_found")
	own, e := f.m.GetStudy(ctx, "human-alice", "research")
	if e != nil || obj(own["my_application"])["status"] != "approved" {
		t.Fatal(own, e)
	}
	ownPage, e := f.m.ListStudies(ctx, "human-alice", 10, "")
	if e != nil || len(arr(ownPage["items"])) != 1 {
		t.Fatal(ownPage, e)
	}
	_, e = f.m.ApplyToStudy(ctx, "human-alice", "research", "new-alias", "", "approved-reapply")
	mgrError(t, e, 409, "study_registration_closed")
	_, e = f.m.ReviewStudyApplication(ctx, "human-alice", "research", text(alice["id"]), "withdraw", "", 2, "withdraw-approved")
	mgrError(t, e, 409, "study_application_not_pending")
	_, e = f.m.CreateJob(ctx, "owner", mgrSpec(), "closure-does-not-bypass")
	mgrError(t, e, 403, "study_participant_not_approved")
}
func TestStudyRejectionWithdrawalRetryIdempotencyAndAudit(t *testing.T) {
	f := newMgrFixture(t)
	ctx := context.Background()
	openStudy(t, f)
	original := applyStudy(t, f, "human-alice", "alice")
	replay, e := f.m.ApplyToStudy(ctx, "human-alice", "research", "alice", "My local data remain private", "apply-human-alice")
	if e != nil || replay["id"] != original["id"] {
		t.Fatal(replay, e)
	}
	_, e = f.m.ApplyToStudy(ctx, "human-alice", "research", "alice", "changed", "apply-human-alice")
	mgrError(t, e, 409, "idempotency_conflict")
	rejected, e := f.m.ReviewStudyApplication(ctx, "owner", "research", text(original["id"]), "reject", "Please clarify the data agreement", 1, "reject-first")
	if e != nil || rejected["status"] != "rejected" {
		t.Fatal(rejected, e)
	}
	replay, e = f.m.ApplyToStudy(ctx, "human-alice", "research", "alice", "My local data remain private", "apply-human-alice")
	if e != nil || replay["status"] != "rejected" {
		t.Fatal("replay returned stale authority", replay, e)
	}
	retried, e := f.m.ApplyToStudy(ctx, "human-alice", "research", "alice", "Updated data agreement", "retry")
	if e != nil || retried["id"] != original["id"] || retried["version"] != int64(3) {
		t.Fatal(retried, e)
	}
	_, e = f.m.ReviewStudyApplication(ctx, "owner", "research", text(original["id"]), "approve", "", 1, "stale-review")
	mgrError(t, e, 409, "study_version_conflict")
	withdrawn, e := f.m.ReviewStudyApplication(ctx, "human-alice", "research", text(original["id"]), "withdraw", "", 3, "withdraw")
	if e != nil || withdrawn["status"] != "withdrawn" || withdrawn["reviewer_id"] != nil {
		t.Fatal(withdrawn, e)
	}
	_, e = f.m.ApplyToStudy(ctx, "human-alice", "research", "alice", "New application", "retry-again")
	if e != nil {
		t.Fatal(e)
	}
	audits, e := f.db.All(ctx, "SELECT * FROM jm_admin_audit WHERE resource_type='study_application' ORDER BY created_at,id")
	if e != nil || len(audits) != 5 {
		t.Fatal(len(audits), e)
	}
	for _, audit := range audits {
		a := obj(audit["after_json"])
		if len(a) != 5 || a["message"] != nil || a["review_reason"] != nil {
			t.Fatal("unsanitized study audit", a)
		}
	}
}
func TestStudyPendingAliasesAreNotReservedAndApprovedAliasesCannotBeReassigned(t *testing.T) {
	f := newMgrFixture(t)
	ctx := context.Background()
	openStudy(t, f)
	one := applyStudy(t, f, "first-person", "alice")
	two := applyStudy(t, f, "second-person", "alice")
	approveStudy(t, f, two)
	_, e := f.m.ReviewStudyApplication(ctx, "owner", "research", text(one["id"]), "approve", "", 1, "approve-conflict")
	mgrError(t, e, 409, "study_participant_id_taken")
	_, e = f.m.ApplyToStudy(ctx, "third-person", "research", "alice", "", "claim-approved")
	mgrError(t, e, 409, "study_participant_id_taken")
	own, e := f.m.GetStudyApplication(ctx, "first-person", "research")
	if e != nil || obj(own["application"])["status"] != "pending" {
		t.Fatal(own, e)
	}
}
func TestStudyVisibilityBoundedPaginationAndPrivateReviews(t *testing.T) {
	f := newMgrFixture(t)
	ctx := context.Background()
	openStudy(t, f)
	for i := 0; i < 3; i++ {
		applyStudy(t, f, fmt.Sprintf("human-%d", i), fmt.Sprintf("person-%d", i))
	}
	f.insert("jm_projects", Object{"id": "private", "name": "Private project"})
	page, e := f.m.ListStudyApplications(ctx, "owner", "research", 1, "")
	if e != nil || len(arr(page["items"])) != 1 || page["next_cursor"] == "" {
		t.Fatal(page, e)
	}
	next, e := f.m.ListStudyApplications(ctx, "owner", "research", 2, text(page["next_cursor"]))
	if e != nil || len(arr(next["items"])) != 2 || next["next_cursor"] != "" {
		t.Fatal(next, e)
	}
	_, e = f.m.ListStudyApplications(ctx, "human-0", "research", 1, "")
	mgrError(t, e, 403, "project_admin_required")
	_, e = f.m.ListStudyApplications(ctx, "human-0", "research", 1, text(page["next_cursor"]))
	mgrError(t, e, 422, "invalid_cursor")
	_, e = f.m.GetStudy(ctx, "human-0", "private")
	mgrError(t, e, 404, "study_not_found")
	_, e = f.m.ListStudies(ctx, "human-0", 101, "")
	mgrError(t, e, 422, "invalid_page_limit")
	first := obj(arr(page["items"])[0])
	_, e = f.m.ReviewStudyApplication(ctx, "human-0", "private", text(first["id"]), "withdraw", "", 1, "foreign")
	mgrError(t, e, 404, "study_not_found")
}
func TestStudyEnableRequiresNoExistingNonterminalJobs(t *testing.T) {
	f := newMgrFixture(t)
	ctx := context.Background()
	studyAdmin(t, f)
	job := f.create("legacy-queued")
	_, e := f.m.PutStudySettings(ctx, "owner", "research", "", true, 1, "enable-busy")
	mgrError(t, e, 409, "study_has_active_jobs")
	row, e := f.db.One(ctx, "SELECT COUNT(*) AS n FROM jm_studies")
	if e != nil || number(row["n"]) != 0 {
		t.Fatal(row, e)
	}
	f.update("jm_jobs", text(job["id"]), Object{"state": "CANCELLED"})
	opened, e := f.m.PutStudySettings(ctx, "owner", "research", "", true, 1, "enable-quiescent")
	if e != nil || opened["registration_enabled"] != true {
		t.Fatal(opened, e)
	}
}
func TestStudyValidationAndChangedAdministrativeAuthority(t *testing.T) {
	f := newMgrFixture(t)
	ctx := context.Background()
	openStudy(t, f)
	for _, pid := range []string{"", "../alice", "alice/path", string([]byte{255})} {
		_, e := f.m.ApplyToStudy(ctx, "applicant", "research", pid, "", "bad-"+fmt.Sprint(len(pid)))
		mgrError(t, e, 422, "invalid_study_application")
	}
	_, e := f.m.ApplyToStudy(ctx, "applicant", "research", "alice", "private\x00data", "bad-control")
	mgrError(t, e, 422, "invalid_study_application")
	app := applyStudy(t, f, "applicant", "alice")
	e = f.db.WithTx(ctx, true, func(tx *store.Tx) error {
		return tx.Update(ctx, "jm_project_members", Object{"project_id": "research", "principal_id": "owner"}, Object{"role": "submitter"})
	})
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.m.ReviewStudyApplication(ctx, "owner", "research", text(app["id"]), "approve", "", 1, "removed-admin")
	mgrError(t, e, 403, "project_admin_required")
}
func TestStudyConcurrentCreateAndFirstEnableSerialize(t *testing.T) {
	testStudyConcurrentCreateAndEnable(t, newMgrFixture(t))
}
func TestStudyPostgreSQLConcurrentCreateAndFirstEnableSerialize(t *testing.T) {
	testStudyConcurrentCreateAndEnable(t, newPostgresMgrFixture(t))
}
func testStudyConcurrentCreateAndEnable(t *testing.T, f *mgrFixture) {
	ctx := context.Background()
	studyAdmin(t, f)
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan struct {
		name string
		err  error
	}, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, e := f.m.CreateJob(ctx, "owner", mgrSpec(), "race-create")
		results <- struct {
			name string
			err  error
		}{"create", e}
	}()
	go func() {
		defer wg.Done()
		<-start
		_, e := f.m.PutStudySettings(ctx, "owner", "research", "", true, 1, "race-enable")
		results <- struct {
			name string
			err  error
		}{"enable", e}
	}()
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for result := range results {
		if result.err == nil {
			successes++
		} else if result.name == "enable" {
			mgrError(t, result.err, 409, "study_has_active_jobs")
		} else {
			mgrError(t, result.err, 403, "study_participant_not_approved")
		}
	}
	if successes != 1 {
		t.Fatal("unsafe first-activation race", successes)
	}
}
func TestStudyPostgreSQLConcurrentApprovalCannotDoubleReview(t *testing.T) {
	f := newPostgresMgrFixture(t)
	ctx := context.Background()
	openStudy(t, f)
	app := applyStudy(t, f, "human-alice", "alice")
	var wg sync.WaitGroup
	out := make(chan error, 2)
	for _, action := range []string{"approve", "reject"} {
		wg.Add(1)
		go func(action string) {
			defer wg.Done()
			_, e := f.m.ReviewStudyApplication(ctx, "owner", "research", text(app["id"]), action, "", 1, "concurrent-"+action)
			out <- e
		}(action)
	}
	wg.Wait()
	close(out)
	success := 0
	for e := range out {
		if e == nil {
			success++
		} else {
			mgrError(t, e, 409, "study_version_conflict")
		}
	}
	if success != 1 {
		t.Fatal(success)
	}
}

func TestStudyRetryOfLegacyFailedJobRequiresApprovedParticipants(t *testing.T) {
	for _, managed := range []bool{false, true} {
		t.Run(fmt.Sprint("managed=", managed), func(t *testing.T) {
			f := newMgrFixture(t)
			ctx := context.Background()
			studyAdmin(t, f)
			spec := mgrSpec()
			if managed {
				spec = managedStudySpec()
			}
			job, e := f.m.CreateJob(ctx, "owner", spec, "before-study")
			if e != nil {
				t.Fatal(e)
			}
			id := text(job["id"])
			f.update("jm_jobs", id, Object{"state": "FAILED"})
			openStudy(t, f)
			_, e = f.m.Retry(ctx, "owner", id, 1, "denied-retry")
			mgrError(t, e, 403, "study_participant_not_approved")
			row, e := f.db.One(ctx, "SELECT COUNT(*) AS n FROM jm_outbox WHERE job_id=? AND topic='prepare_retry'", id)
			if e != nil || number(row["n"]) != 0 {
				t.Fatal("unapproved retry requested effects", row, e)
			}
			for _, pid := range []string{"alice", "bob"} {
				approveStudy(t, f, applyStudy(t, f, "human-"+pid, pid))
			}
			retried, e := f.m.Retry(ctx, "owner", id, 1, "approved-retry")
			if e != nil || retried["state"] != "RECONCILING" {
				t.Fatal(retried, e)
			}
		})
	}
}
func TestStudyConcurrentRetryAndFirstEnableSerialize(t *testing.T) {
	testStudyConcurrentRetryAndEnable(t, newMgrFixture(t))
}
func TestStudyPostgreSQLConcurrentRetryAndFirstEnableSerialize(t *testing.T) {
	testStudyConcurrentRetryAndEnable(t, newPostgresMgrFixture(t))
}
func testStudyConcurrentRetryAndEnable(t *testing.T, f *mgrFixture) {
	ctx := context.Background()
	studyAdmin(t, f)
	job, e := f.m.CreateJob(ctx, "owner", managedStudySpec(), "old-managed")
	if e != nil {
		t.Fatal(e)
	}
	id := text(job["id"])
	f.update("jm_jobs", id, Object{"state": "FAILED"})
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan struct {
		name string
		err  error
	}, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, e := f.m.Retry(ctx, "owner", id, 1, "race-retry")
		results <- struct {
			name string
			err  error
		}{"retry", e}
	}()
	go func() {
		defer wg.Done()
		<-start
		_, e := f.m.PutStudySettings(ctx, "owner", "research", "", true, 1, "race-enable")
		results <- struct {
			name string
			err  error
		}{"enable", e}
	}()
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for result := range results {
		if result.err == nil {
			successes++
		} else if result.name == "enable" {
			mgrError(t, result.err, 409, "study_has_active_jobs")
		} else {
			mgrError(t, result.err, 403, "study_participant_not_approved")
		}
	}
	if successes != 1 {
		t.Fatal("unsafe retry activation race", successes)
	}
}
