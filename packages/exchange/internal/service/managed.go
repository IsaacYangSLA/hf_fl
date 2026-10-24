package service

import (
	"context"
	"regexp"
	"sort"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/schema"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/store"
)

var workloadThumbprint = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func managedText(value any, limit int) (string, bool) {
	valueString, ok := value.(string)
	return valueString, ok && utf8.RuneCountInString(valueString) >= 1 && utf8.RuneCountInString(valueString) <= limit
}

func managedRoles(value any) ([]string, bool) {
	values, ok := domain.Strings(value)
	if !ok {
		return nil, false
	}
	seen := map[string]bool{}
	for _, role := range values {
		switch role {
		case "reader", "contributor", "publisher", "admin":
			seen[role] = true
		default:
			return nil, false
		}
	}
	result := make([]string, 0, len(seen))
	for role := range seen {
		result = append(result, role)
	}
	sort.Strings(result)
	return result, true
}

func managedContains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// RequireProvisioner checks the service identity, not a mutable space role.
func (s *Service) RequireProvisioner(p domain.Principal) error {
	if s.Settings.Auth.WorkloadIssuer == "" || p.Workload != nil ||
		!managedContains(s.Settings.Auth.ProvisioningPrincipalIDs, p.ID) {
		return domain.Err(403, "provisioning_principal_required")
	}
	return nil
}

// MatchingGrant must run inside the same space transaction as the command.
func (s *Service) MatchingGrant(ctx context.Context, tx *store.Tx, space, member Object, p domain.Principal, managed Object) (Object, error) {
	identity := p.Workload
	if s.Settings.Auth.WorkloadIssuer == "" || identity == nil || managed == nil ||
		managed["retired_at"] != nil || identity.SpaceID != str(space["id"]) {
		return nil, domain.Err(404, "space_not_found")
	}
	grant, err := tx.One(ctx, "SELECT * FROM v2_workload_grants WHERE id=?", identity.GrantID)
	if err != nil {
		return nil, err
	}
	now, err := tx.Now(ctx)
	if err != nil {
		return nil, err
	}
	if grant == nil || !flag(grant["enabled"]) || decimal(grant["expires_at"]) <= now || identity.ExpiresAt <= now ||
		str(grant["space_id"]) != str(space["id"]) || str(grant["principal_id"]) != p.ID ||
		str(grant["subject"]) != p.Subject || str(grant["job_id"]) != str(managed["job_id"]) ||
		str(grant["job_id"]) != identity.JobID || str(grant["attempt_id"]) != identity.AttemptID ||
		str(grant["component_id"]) != identity.ComponentID || num(grant["epoch"]) != identity.Epoch ||
		str(grant["certificate_thumbprint"]) != identity.CertificateThumbprint ||
		!equal(grant["bindings"], member["bindings"]) {
		return nil, domain.Err(403, "workload_grant_invalid")
	}
	for _, role := range stringsOf(member["roles"]) {
		if managedContains(stringsOf(grant["roles"]), role) {
			return grant, nil
		}
	}
	return nil, domain.Err(403, "workload_grant_invalid")
}

func (s *Service) IsManagedSpace(ctx context.Context, sid string) (bool, error) {
	var found bool
	err := s.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		row, err := tx.One(ctx, "SELECT space_id FROM v2_managed_spaces WHERE space_id=?", sid)
		found = row != nil
		return err
	})
	return found, err
}

func grantDict(grant Object) Object {
	result := Object{}
	for _, name := range []string{
		"principal_id", "space_id", "subject", "job_id", "attempt_id", "component_id", "epoch",
		"roles", "bindings", "certificate_thumbprint", "expires_at", "enabled", "created_at", "revoked_at",
	} {
		result[name] = grant[name]
	}
	result["grant_id"] = grant["id"]
	return result
}

func managedState(ctx context.Context, tx *store.Tx, managed Object) (Object, error) {
	sid := str(managed["space_id"])
	blobs, err := tx.All(ctx, "SELECT state FROM v2_blobs WHERE space_id=?", sid)
	if err != nil {
		return nil, err
	}
	pending := false
	for _, blob := range blobs {
		pending = pending || str(blob["state"]) != "cleaned"
	}
	attempts, err := tx.All(ctx, "SELECT a.mutation_tokens FROM v2_transfer_attempts a JOIN v2_blobs b ON b.id=a.blob_id WHERE b.space_id=?", sid)
	if err != nil {
		return nil, err
	}
	for _, attempt := range attempts {
		pending = pending || mutationTokensPending(attempt["mutation_tokens"])
	}
	status := "active"
	if managed["retired_at"] != nil {
		status = "retired"
	}
	return Object{
		"space_id": sid, "job_id": managed["job_id"], "managed": true,
		"status": status, "retired_at": managed["retired_at"],
		"cleanup_pending":     pending && managed["retired_at"] != nil,
		"provenance_retained": true,
	}, nil
}

func (s *Service) EnableManagedSpace(ctx context.Context, p domain.Principal, sid string, body Object, key string) (Object, error) {
	if err := s.RequireProvisioner(p); err != nil {
		return nil, err
	}
	jobID, ok := managedText(body["job_id"], 128)
	if !ok {
		return nil, domain.Err(422, "invalid_job_binding")
	}
	var result Object
	err := s.WithSpace(ctx, sid, p, true, false, func(tx *store.Tx, space, member Object) error {
		if err := Require(member, "admin"); err != nil {
			return err
		}
		var err error
		result, err = s.Once(ctx, tx, space, p, "space.managed", key, body, func() (Object, error) {
			existing, err := tx.One(ctx, "SELECT * FROM v2_managed_spaces WHERE space_id=?", sid)
			if err != nil {
				return nil, err
			}
			if existing != nil {
				if str(existing["job_id"]) != jobID {
					return nil, domain.Err(409, "managed_space_binding_immutable")
				}
			} else {
				foreign, err := tx.One(ctx, "SELECT space_id FROM v2_managed_spaces WHERE job_id=?", jobID)
				if err != nil {
					return nil, err
				}
				if foreign != nil {
					return nil, domain.Err(409, "managed_job_space_conflict")
				}
				now, err := tx.Now(ctx)
				if err != nil {
					return nil, err
				}
				if err = tx.Insert(ctx, "v2_managed_spaces", Object{"space_id": sid, "job_id": jobID, "created_at": now}); err != nil {
					return nil, err
				}
				if err = s.Emit(ctx, tx, sid, "space.managed_enabled", p, nil, Object{"job_id": jobID}); err != nil {
					return nil, err
				}
			}
			return Object{"space_id": sid, "job_id": jobID, "managed": true}, nil
		})
		return err
	})
	return result, err
}

func (s *Service) GetManagedSpace(ctx context.Context, p domain.Principal, sid string) (Object, error) {
	var result Object
	err := s.WithSpace(ctx, sid, p, false, false, func(tx *store.Tx, _ Object, member Object) error {
		if err := Require(member, "reader", "admin"); err != nil {
			return err
		}
		managed, err := tx.One(ctx, "SELECT * FROM v2_managed_spaces WHERE space_id=?", sid)
		if err != nil {
			return err
		}
		if managed == nil {
			return domain.Err(404, "managed_space_not_found")
		}
		result, err = managedState(ctx, tx, managed)
		return err
	})
	return result, err
}

func (s *Service) RetireManagedSpace(ctx context.Context, p domain.Principal, sid string, body Object, key string) (Object, error) {
	if err := s.RequireProvisioner(p); err != nil {
		return nil, err
	}
	jobID, ok := managedText(body["job_id"], 128)
	if !ok {
		return nil, domain.Err(422, "invalid_job_binding")
	}
	var result Object
	err := s.WithSpace(ctx, sid, p, true, true, func(tx *store.Tx, space, member Object) error {
		if err := Require(member, "admin"); err != nil {
			return err
		}
		managed, err := tx.One(ctx, "SELECT * FROM v2_managed_spaces WHERE space_id=?", sid)
		if err != nil {
			return err
		}
		if managed == nil || str(managed["job_id"]) != jobID {
			return domain.Err(409, "managed_space_binding_required")
		}
		result, err = s.Once(ctx, tx, space, p, "space.managed.retire", key, body, func() (Object, error) {
			enabled, err := tx.One(ctx, "SELECT id FROM v2_workload_grants WHERE space_id=? AND enabled=? LIMIT 1", sid, true)
			if err != nil {
				return nil, err
			}
			if enabled != nil {
				return nil, domain.Err(409, "workload_revocation_required")
			}
			if managed["retired_at"] == nil {
				now, err := tx.Now(ctx)
				if err != nil {
					return nil, err
				}
				managed["retired_at"] = now
				if err = tx.Update(ctx, "v2_managed_spaces", Object{"space_id": sid}, Object{"retired_at": now}); err != nil {
					return nil, err
				}
				records, err := tx.All(ctx, "SELECT * FROM v2_records WHERE space_id=?", sid)
				if err != nil {
					return nil, err
				}
				for _, record := range records {
					state := "cancelled"
					if str(record["state"]) == "published" {
						state = "withdrawn"
					}
					if err = s.ReleaseRecord(ctx, tx, space, record, state); err != nil {
						return nil, err
					}
				}
				if err = s.Emit(ctx, tx, sid, "space.managed_retired", p, nil, Object{"job_id": jobID}); err != nil {
					return nil, err
				}
			}
			return managedState(ctx, tx, managed)
		})
		return err
	})
	return result, err
}

func (s *Service) CreateWorkloadGrant(ctx context.Context, p domain.Principal, sid string, body Object, key string) (Object, error) {
	if err := s.RequireProvisioner(p); err != nil {
		return nil, err
	}
	for field, limit := range map[string]int{"subject": 256, "job_id": 128, "attempt_id": 128, "component_id": 128} {
		if _, ok := managedText(body[field], limit); !ok {
			return nil, domain.Err(422, "invalid_workload_binding")
		}
	}
	epoch, ok := domain.Int64(body["epoch"])
	if !ok || epoch < 1 {
		return nil, domain.Err(422, "invalid_workload_epoch")
	}
	thumbprint, ok := body["certificate_thumbprint"].(string)
	if !ok || !workloadThumbprint.MatchString(thumbprint) {
		return nil, domain.Err(422, "invalid_certificate_thumbprint")
	}
	roles, ok := managedRoles(body["roles"])
	if !ok || len(roles) == 0 {
		return nil, domain.Err(422, "invalid_roles")
	}
	bindings, ok := get(body, "bindings", Object{}).(map[string]any)
	if !ok {
		return nil, domain.Err(422, "invalid_bindings")
	}
	if _, err := schema.MetadataSize(bindings); err != nil {
		return nil, err
	}
	expiry, ok := domain.Float(body["expires_at"])
	if !ok {
		return nil, domain.Err(422, "invalid_grant_expiry")
	}
	pid := domain.PrincipalID(s.Settings.Auth.WorkloadIssuer, str(body["subject"]))
	var result Object
	err := s.WithSpace(ctx, sid, p, true, false, func(tx *store.Tx, space, caller Object) error {
		if err := Require(caller, "admin"); err != nil {
			return err
		}
		var err error
		result, err = s.Once(ctx, tx, space, p, "workload.grant", key, body, func() (Object, error) {
			managed, err := tx.One(ctx, "SELECT * FROM v2_managed_spaces WHERE space_id=?", sid)
			if err != nil {
				return nil, err
			}
			if managed == nil || str(managed["job_id"]) != str(body["job_id"]) {
				return nil, domain.Err(409, "managed_space_binding_required")
			}
			revoked, err := tx.One(ctx, "SELECT attempt_id FROM v2_workload_revocations WHERE space_id=? AND attempt_id=?", sid, body["attempt_id"])
			if err != nil {
				return nil, err
			}
			if revoked != nil {
				return nil, domain.Err(409, "attempt_already_revoked")
			}
			member, err := tx.One(ctx, "SELECT * FROM v2_members WHERE space_id=? AND principal_id=?", sid, pid)
			if err != nil {
				return nil, err
			}
			if member == nil || !equal(bindings, member["bindings"]) {
				return nil, domain.Err(403, "workload_membership_required")
			}
			for _, role := range roles {
				if !managedContains(stringsOf(member["roles"]), role) {
					return nil, domain.Err(403, "workload_membership_required")
				}
			}
			now, err := tx.Now(ctx)
			if err != nil {
				return nil, err
			}
			if expiry <= now || expiry > now+30*86400 {
				return nil, domain.Err(422, "invalid_grant_expiry")
			}
			previous, err := tx.All(ctx, "SELECT * FROM v2_workload_grants WHERE space_id=? AND principal_id=?", sid, pid)
			if err != nil {
				return nil, err
			}
			var highest int64
			for _, old := range previous {
				if str(old["component_id"]) != str(body["component_id"]) {
					return nil, domain.Err(409, "workload_component_immutable")
				}
				if num(old["epoch"]) > highest {
					highest = num(old["epoch"])
				}
			}
			if epoch < highest {
				return nil, domain.Err(409, "stale_workload_epoch")
			}
			for _, old := range previous {
				if flag(old["enabled"]) && (str(old["attempt_id"]) != str(body["attempt_id"]) || num(old["epoch"]) != epoch) {
					return nil, domain.Err(409, "previous_attempt_not_revoked")
				}
			}
			for _, old := range previous {
				if str(old["attempt_id"]) != str(body["attempt_id"]) && num(old["epoch"]) >= epoch {
					return nil, domain.Err(409, "stale_workload_epoch")
				}
			}
			gid, err := domain.Hash([]any{sid, p.ID, key})
			if err != nil {
				return nil, err
			}
			grant := Object{
				"id": gid, "space_id": sid, "principal_id": pid, "subject": body["subject"],
				"job_id": body["job_id"], "attempt_id": body["attempt_id"], "component_id": body["component_id"],
				"epoch": epoch, "roles": roles, "bindings": domain.CloneMap(bindings),
				"certificate_thumbprint": thumbprint, "expires_at": expiry, "enabled": true, "created_at": now,
			}
			if err = tx.Insert(ctx, "v2_workload_grants", grant); err != nil {
				return nil, err
			}
			if err = s.Emit(ctx, tx, sid, "workload.granted", p, nil, Object{"grant_id": gid, "principal_id": pid, "attempt_id": body["attempt_id"], "epoch": epoch}); err != nil {
				return nil, err
			}
			return grantDict(grant), nil
		})
		return err
	})
	return result, err
}

func (s *Service) RevokeWorkloadGrants(ctx context.Context, p domain.Principal, sid string, body Object, key string) (Object, error) {
	if err := s.RequireProvisioner(p); err != nil {
		return nil, err
	}
	attemptID, ok := managedText(body["attempt_id"], 128)
	if !ok {
		return nil, domain.Err(422, "invalid_attempt_binding")
	}
	var result Object
	err := s.WithSpace(ctx, sid, p, true, true, func(tx *store.Tx, space, caller Object) error {
		if err := Require(caller, "admin"); err != nil {
			return err
		}
		var err error
		result, err = s.Once(ctx, tx, space, p, "workload.revoke", key, body, func() (Object, error) {
			now, err := tx.Now(ctx)
			if err != nil {
				return nil, err
			}
			tombstone, err := tx.One(ctx, "SELECT * FROM v2_workload_revocations WHERE space_id=? AND attempt_id=?", sid, attemptID)
			if err != nil {
				return nil, err
			}
			if tombstone == nil {
				if err = tx.Insert(ctx, "v2_workload_revocations", Object{"space_id": sid, "attempt_id": attemptID, "revoked_at": now}); err != nil {
					return nil, err
				}
			} else {
				now = decimal(tombstone["revoked_at"])
			}
			grants, err := tx.All(ctx, "SELECT * FROM v2_workload_grants WHERE space_id=? AND attempt_id=? AND enabled=?", sid, attemptID, true)
			if err != nil {
				return nil, err
			}
			for _, grant := range grants {
				if err = tx.Update(ctx, "v2_workload_grants", Object{"id": grant["id"]}, Object{"enabled": false, "revoked_at": now}); err != nil {
					return nil, err
				}
			}
			if err = s.Emit(ctx, tx, sid, "workload.revoked", p, nil, Object{"attempt_id": attemptID, "revoked": len(grants)}); err != nil {
				return nil, err
			}
			return Object{"attempt_id": attemptID, "revoked": len(grants), "revoked_at": now}, nil
		})
		return err
	})
	return result, err
}

func (s *Service) GetWorkloadGrant(ctx context.Context, p domain.Principal, sid, grantID string) (Object, error) {
	if err := s.RequireProvisioner(p); err != nil {
		return nil, err
	}
	var result Object
	err := s.WithSpace(ctx, sid, p, false, false, func(tx *store.Tx, _ Object, member Object) error {
		if err := Require(member, "admin"); err != nil {
			return err
		}
		grant, err := tx.One(ctx, "SELECT * FROM v2_workload_grants WHERE id=?", grantID)
		if err != nil {
			return err
		}
		if grant == nil || str(grant["space_id"]) != sid {
			return domain.Err(404, "workload_grant_not_found")
		}
		result = grantDict(grant)
		return nil
	})
	return result, err
}

func (s *Service) VerifyWorkloadGrant(ctx context.Context, p domain.Principal, sid string) (Object, error) {
	if p.Workload == nil {
		return nil, domain.Err(403, "workload_required")
	}
	var result Object
	err := s.WithSpace(ctx, sid, p, false, false, func(tx *store.Tx, _ Object, member Object) error {
		grant, err := tx.One(ctx, "SELECT * FROM v2_workload_grants WHERE id=?", p.Workload.GrantID)
		if err != nil {
			return err
		}
		// WithSpace already checked this row in the same transaction snapshot.
		if grant == nil {
			return domain.Err(403, "workload_grant_invalid")
		}
		result = grantDict(grant)
		result["effective_roles"] = append([]string{}, stringsOf(member["roles"])...)
		return nil
	})
	return result, err
}
