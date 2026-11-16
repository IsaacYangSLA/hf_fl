package store

import (
	"context"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

// StudyParticipantPrincipal binds an execution's participant alias to the human
// who personally applied and was approved. Legacy projects have no study policy.
// An approved alias is permanent: public study operations cannot revoke,
// reassign, or withdraw it. Cleanup uses its separate existing authority path.
func StudyParticipantPrincipal(ctx context.Context, tx *Tx, projectID, participantID string) (string, error) {
	study, err := tx.One(ctx, "SELECT enabled FROM jm_studies WHERE project_id=?", projectID)
	if err != nil {
		return "", err
	}
	enabled, _ := study["enabled"].(bool)
	if !enabled {
		return "", nil
	}
	application, err := tx.One(ctx, "SELECT principal_id FROM jm_study_applications WHERE project_id=? AND participant_id=? AND status='approved'", projectID, participantID)
	if err != nil {
		return "", err
	}
	principal, _ := application["principal_id"].(string)
	if principal == "" {
		return "", domain.Err(403, "study_participant_not_approved")
	}
	return principal, nil
}
