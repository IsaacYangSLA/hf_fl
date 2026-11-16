package provision

import (
	"context"
	"errors"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
	"testing"
)

func TestProvisioningRequiresCurrentStudyApprovalForEveryMode(t *testing.T) {
	for _, mode := range []string{"external", "managed"} {
		t.Run(mode, func(t *testing.T) {
			h := setup(t)
			ctx := context.Background()
			for i := range h.spec.Participants {
				h.spec.Participants[i].Mode = mode
			}
			e := h.db.WithTx(ctx, true, func(tx *store.Tx) error {
				return tx.Insert(ctx, "jm_studies", map[string]any{"project_id": "research", "enabled": true, "registration_open": false})
			})
			if e != nil {
				t.Fatal(e)
			}
			_, _, e = h.p.validateCatalog(ctx, h.spec)
			var known *domain.Error
			if !errors.As(e, &known) || known.Code != "study_participant_not_approved" {
				t.Fatal("provisioning accepted unapproved study participants", e)
			}
			for _, pid := range []string{"alice", "bob"} {
				e = h.db.WithTx(ctx, true, func(tx *store.Tx) error {
					return tx.Insert(ctx, "jm_study_applications", map[string]any{"project_id": "research", "principal_id": "human-" + pid, "participant_id": pid, "status": "approved"})
				})
				if e != nil {
					t.Fatal(e)
				}
			}
			if _, _, e = h.p.validateCatalog(ctx, h.spec); e != nil {
				t.Fatal("approved participant catalog rejected", e)
			}
		})
	}
}
