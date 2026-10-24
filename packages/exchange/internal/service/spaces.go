package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/profiles"
	schema "github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/schema"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/store"
)

func (s *Service) CreateSpace(ctx context.Context, p domain.Principal, body Object, key string) (Object, error) {
	if p.Workload != nil || (!p.BootstrapAdmin && (s.Settings.Auth.AdminSubject == "" || p.Subject != s.Settings.Auth.AdminSubject)) {
		return nil, domain.Err(403, "bootstrap_admin_required")
	}
	if key == "" || utf8.RuneCountInString(key) > 128 {
		return nil, domain.Err(422, "idempotency_key_required")
	}
	profileName := get(body, "profile", "generic.v1")
	if _, e := profiles.Get(profileName); e != nil {
		return nil, e
	}
	name, ok := body["name"].(string)
	if !ok || name == "" || utf8.RuneCountInString(name) > 128 {
		return nil, domain.Err(422, "invalid_space_name")
	}
	encoded, e := domain.CanonicalJSON([]any{p.ID, key})
	if e != nil {
		return nil, e
	}
	sum := sha256.Sum256(encoded)
	sid := hex.EncodeToString(sum[:])[:32]
	var result Object
	e = s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		if tx.Dialect == "postgresql" {
			if _, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext(?))", sid); e != nil {
				return e
			}
		}
		space, e := tx.One(ctx, "SELECT * FROM v2_spaces WHERE id=?"+tx.ForUpdate(), sid)
		if e != nil {
			return e
		}
		if space == nil {
			values := Object{"id": sid, "name": name, "profile": profileName}
			defaults := Object{"quota_bytes": int64(10 * 1024 * 1024 * 1024), "principal_quota_bytes": int64(10 * 1024 * 1024 * 1024), "quota_records": int64(100000), "quota_metadata_bytes": int64(1024 * 1024 * 1024)}
			for field, fallback := range defaults {
				v := get(body, field, fallback)
				n, ok := domain.Int64(v)
				if !ok || n < 1 {
					return domain.Err(422, "invalid_quota")
				}
				values[field] = n
			}
			if e = tx.Insert(ctx, "v2_spaces", values); e != nil {
				return e
			}
			if e = tx.Insert(ctx, "v2_members", Object{"space_id": sid, "principal_id": p.ID, "subject": p.Subject, "roles": allRoles, "bindings": Object{}}); e != nil {
				return e
			}
			space, e = tx.One(ctx, "SELECT * FROM v2_spaces WHERE id=?", sid)
			if e != nil {
				return e
			}
			if e = s.Emit(ctx, tx, sid, "space.created", p, nil, nil); e != nil {
				return e
			}
		}
		member, e := tx.One(ctx, "SELECT * FROM v2_members WHERE space_id=? AND principal_id=?", sid, p.ID)
		if e != nil {
			return e
		}
		if member == nil || len(stringsOf(member["roles"])) == 0 {
			return domain.Err(404, "space_not_found")
		}
		result, e = s.Once(ctx, tx, space, p, "space.create", key, body, func() (Object, error) { return spaceDict(space), nil })
		return e
	})
	return result, e
}
func (s *Service) GetSpace(ctx context.Context, p domain.Principal, sid string) (Object, error) {
	var result Object
	e := s.WithSpace(ctx, sid, p, false, false, func(tx *store.Tx, space, member Object) error {
		result = spaceDict(space)
		managed, e := tx.One(ctx, "SELECT * FROM v2_managed_spaces WHERE space_id=?", sid)
		if e != nil {
			return e
		}
		if managed != nil {
			result["managed"] = true
			result["job_id"] = managed["job_id"]
			result["retired_at"] = managed["retired_at"]
		}
		return nil
	})
	return result, e
}
func (s *Service) UpdateSpaceLimits(ctx context.Context, p domain.Principal, sid string, body Object) (Object, error) {
	allowed := map[string]bool{"quota_bytes": true, "principal_quota_bytes": true, "quota_records": true, "quota_metadata_bytes": true}
	if len(body) == 0 {
		return nil, domain.Err(422, "invalid_quota_fields")
	}
	for k, v := range body {
		if !allowed[k] {
			return nil, domain.Err(422, "invalid_quota_fields")
		}
		n, ok := domain.Int64(v)
		if !ok || n < 1 {
			return nil, domain.Err(422, "invalid_quota")
		}
	}
	var result Object
	e := s.WithSpace(ctx, sid, p, true, false, func(tx *store.Tx, space, member Object) error {
		if e := Require(member, "admin"); e != nil {
			return e
		}
		usage := Object{"quota_bytes": num(space["allocated"]) + num(space["reclaiming"]), "quota_records": space["record_count"], "quota_metadata_bytes": space["metadata_bytes"]}
		if _, ok := body["principal_quota_bytes"]; ok {
			row, e := tx.One(ctx, "SELECT CAST(COALESCE(MAX(used),0) AS BIGINT) AS used FROM (SELECT SUM(b.size) AS used FROM v2_blobs b JOIN v2_records r ON r.id=b.record_id WHERE r.space_id=? AND b.state<>? GROUP BY r.creator) AS principal_usage", sid, "cleaned")
			if e != nil {
				return e
			}
			usage["principal_quota_bytes"] = row["used"]
		}
		for k, v := range body {
			if num(v) < num(usage[k]) {
				return domain.Err(409, "quota_below_current_usage")
			}
		}
		values := clone(body)
		values["generation"] = num(space["generation"]) + 1
		if e := update(ctx, tx, "v2_spaces", Object{"id": sid}, space, values); e != nil {
			return e
		}
		if e := s.Emit(ctx, tx, sid, "space.limits_updated", p, nil, clone(body)); e != nil {
			return e
		}
		result = spaceDict(space)
		return nil
	})
	return result, e
}
func (s *Service) GetMembership(ctx context.Context, p domain.Principal, sid string) (Object, error) {
	var result Object
	e := s.WithSpace(ctx, sid, p, false, false, func(_ *store.Tx, _ Object, member Object) error { result = memberDict(member); return nil })
	return result, e
}
func (s *Service) ListMembers(ctx context.Context, p domain.Principal, sid string) (Object, error) {
	var result Object
	e := s.WithSpace(ctx, sid, p, false, false, func(tx *store.Tx, _ Object, member Object) error {
		if e := Require(member, "admin"); e != nil {
			return e
		}
		rows, e := tx.All(ctx, "SELECT * FROM v2_members WHERE space_id=? ORDER BY principal_id", sid)
		if e != nil {
			return e
		}
		items := []Object{}
		for _, r := range rows {
			items = append(items, memberDict(r))
		}
		result = Object{"items": items}
		return nil
	})
	return result, e
}
func (s *Service) PutMember(ctx context.Context, p domain.Principal, sid, memberID string, body Object) (Object, error) {
	var result Object
	e := s.WithSpace(ctx, sid, p, true, false, func(tx *store.Tx, space, caller Object) error {
		if e := Require(caller, "admin"); e != nil {
			return e
		}
		if memberID == "" || utf8.RuneCountInString(memberID) > 64 {
			return domain.Err(422, "invalid_principal_id")
		}
		subject := body["subject"]
		if subject != nil {
			v, ok := subject.(string)
			if !ok || v == "" || utf8.RuneCountInString(v) > 256 {
				return domain.Err(422, "invalid_subject")
			}
		}
		roles, ok := domain.Strings(get(body, "roles", []string{}))
		if !ok {
			return domain.Err(422, "invalid_roles")
		}
		for _, role := range roles {
			if !contains(allRoles, role) {
				return domain.Err(422, "invalid_roles")
			}
		}
		bindings, ok := get(body, "bindings", Object{}).(map[string]any)
		if !ok {
			return domain.Err(422, "invalid_bindings")
		}
		if _, e := schema.MetadataSize(bindings); e != nil {
			return e
		}
		others, e := tx.All(ctx, "SELECT * FROM v2_members WHERE space_id=? AND principal_id<>?", sid, memberID)
		if e != nil {
			return e
		}
		otherBindings := []Object{}
		for _, other := range others {
			otherBindings = append(otherBindings, obj(other["bindings"]))
		}
		profile, e := profiles.Get(space["profile"])
		if e != nil {
			return e
		}
		if e = profile.ValidateBindings(bindings, otherBindings); e != nil {
			return e
		}
		current, e := tx.One(ctx, "SELECT * FROM v2_members WHERE space_id=? AND principal_id=?", sid, memberID)
		if e != nil {
			return e
		}
		if current != nil && hasRole(current, "admin") && !contains(roles, "admin") {
			found := false
			for _, other := range others {
				if hasRole(other, "admin") {
					found = true
					break
				}
			}
			if !found {
				return domain.Err(409, "last_admin")
			}
		}
		values := Object{"roles": unique(roles), "bindings": clone(bindings), "subject": subject}
		if current == nil {
			current = clone(values)
			current["space_id"] = sid
			current["principal_id"] = memberID
			if e = tx.Insert(ctx, "v2_members", current); e != nil {
				return e
			}
		} else if e = update(ctx, tx, "v2_members", Object{"space_id": sid, "principal_id": memberID}, current, values); e != nil {
			return e
		}
		if e = s.Emit(ctx, tx, sid, "membership.changed", p, nil, Object{"principal_id": memberID}); e != nil {
			return e
		}
		result = memberDict(current)
		return nil
	})
	return result, e
}
