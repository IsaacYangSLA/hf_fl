package participants

import (
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
	"testing"
)

func TestParticipantStudyApprovalRequiredForEnrollmentAndCurrentAuthority(t *testing.T) {
	f := newParticipantFixture(t)
	e := f.db.WithTx(f.ctx, true, func(tx *store.Tx) error {
		if e := tx.Insert(f.ctx, "jm_studies", map[string]any{"project_id": "project", "enabled": true, "registration_open": true}); e != nil {
			return e
		}
		return tx.Insert(f.ctx, "jm_study_applications", map[string]any{"id": "application-alice", "project_id": "project", "principal_id": "verified-human-alice", "participant_id": "alice", "status": "pending"})
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Enroll(f.ctx, "owner", "job", "alice", "node-alice", 1, "denied-pending"); e == nil {
		t.Fatal("pending applicant acquired execution enrollment")
	}
	e = f.db.WithTx(f.ctx, true, func(tx *store.Tx) error {
		return tx.Update(f.ctx, "jm_study_applications", map[string]any{"id": "application-alice"}, map[string]any{"status": "approved"})
	})
	if e != nil {
		t.Fatal(e)
	}
	f.enroll()
	f.budget()
	if _, e = f.s.BootstrapCredentials(f.ctx, f.actor.GrantID); e != nil {
		t.Fatal(e)
	}
	if !f.s.SourceAccessValid(f.ctx, f.actor) || !f.s.CheckNodeGrant(f.ctx, f.actor) {
		t.Fatal("approved binding did not grant expected execution authority")
	}
	// A retained node token cannot replace current enrollment authority. This
	// simulates administrative corruption/recovery, not a public revocation API.
	e = f.db.WithTx(f.ctx, true, func(tx *store.Tx) error {
		return tx.Update(f.ctx, "jm_study_applications", map[string]any{"id": "application-alice"}, map[string]any{"status": "rejected"})
	})
	if e != nil {
		t.Fatal(e)
	}
	if f.s.SourceAccessValid(f.ctx, f.actor) || f.s.CheckNodeGrant(f.ctx, f.actor) {
		t.Fatal("node authority bypassed current approved-study binding")
	}
}
