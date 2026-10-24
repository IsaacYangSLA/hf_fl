package service

import (
	"context"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/profiles"
	schema "github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/schema"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/store"
)

func validatePolicy(body Object) ([]string, string, error) {
	roles, ok := domain.Strings(get(body, "publish_roles", []string{"contributor", "publisher"}))
	if !ok || len(roles) == 0 {
		return nil, "", domain.Err(422, "invalid_publish_roles")
	}
	for _, r := range roles {
		if r != "contributor" && r != "publisher" {
			return nil, "", domain.Err(422, "invalid_publish_roles")
		}
	}
	visibility, ok := get(body, "visibility", "shared").(string)
	if !ok || (visibility != "shared" && visibility != "private") {
		return nil, "", domain.Err(422, "invalid_visibility")
	}
	return unique(roles), visibility, nil
}
func (s *Service) RegisterType(ctx context.Context, p domain.Principal, sid, kind string, body Object, key string) (Object, error) {
	var result Object
	e := s.WithSpace(ctx, sid, p, true, false, func(tx *store.Tx, space, member Object) error {
		if e := Require(member, "admin"); e != nil {
			return e
		}
		if _, e := schema.ValidateKind(kind); e != nil {
			return e
		}
		spec, ok := get(body, "schema", Object{}).(map[string]any)
		if !ok {
			return domain.Err(422, "invalid_schema")
		}
		if e := schema.ValidateSchema(spec); e != nil {
			return e
		}
		profile, e := profiles.Get(space["profile"])
		if e != nil {
			return e
		}
		if e = profile.ValidateType(kind, spec); e != nil {
			return e
		}
		policyBody := profile.PolicyDefaults(kind)
		for k, v := range body {
			policyBody[k] = v
		}
		roles, visibility, e := validatePolicy(policyBody)
		if e != nil {
			return e
		}
		if e = profile.ValidatePolicy(kind, roles, visibility); e != nil {
			return e
		}
		result, e = s.Once(ctx, tx, space, p, "type.register:"+kind, key, body, func() (Object, error) {
			row, e := tx.One(ctx, "SELECT COALESCE(MAX(revision),0) AS revision FROM v2_schema_revisions WHERE space_id=? AND kind=?", sid, kind)
			if e != nil {
				return nil, e
			}
			now, e := tx.Now(ctx)
			if e != nil {
				return nil, e
			}
			digest, e := schema.SchemaDigest(spec)
			if e != nil {
				return nil, e
			}
			revision := Object{"id": domain.NewID(), "space_id": sid, "kind": kind, "revision": num(row["revision"]) + 1, "schema": spec, "profile_version": space["profile"], "digest": digest, "dialect": get(spec, "$schema", schema.Dialect), "created_at": now}
			if e = tx.Insert(ctx, "v2_schema_revisions", revision); e != nil {
				return nil, e
			}
			policy, e := tx.One(ctx, "SELECT * FROM v2_kind_policies WHERE space_id=? AND kind=?", sid, kind)
			if e != nil {
				return nil, e
			}
			if policy == nil {
				if e = tx.Insert(ctx, "v2_kind_policies", Object{"space_id": sid, "kind": kind, "publish_roles": roles, "visibility": visibility}); e != nil {
					return nil, e
				}
			}
			if e = s.Emit(ctx, tx, sid, "type.registered", p, nil, Object{"kind": kind, "revision": revision["revision"]}); e != nil {
				return nil, e
			}
			return typeDict(revision), nil
		})
		return e
	})
	return result, e
}
func (s *Service) GetType(ctx context.Context, p domain.Principal, sid, kind string, revision int64) (Object, error) {
	var result Object
	e := s.WithSpace(ctx, sid, p, false, false, func(tx *store.Tx, _ Object, _ Object) error {
		row, e := tx.One(ctx, "SELECT * FROM v2_schema_revisions WHERE space_id=? AND kind=? AND revision=?", sid, kind, revision)
		if e != nil {
			return e
		}
		if row == nil {
			return domain.Err(404, "type_not_found")
		}
		result = typeDict(row)
		return nil
	})
	return result, e
}
func (s *Service) ListTypes(ctx context.Context, p domain.Principal, sid string) (Object, error) {
	var result Object
	e := s.WithSpace(ctx, sid, p, false, false, func(tx *store.Tx, _ Object, _ Object) error {
		rows, e := tx.All(ctx, "SELECT * FROM v2_schema_revisions WHERE space_id=? ORDER BY kind,revision", sid)
		if e != nil {
			return e
		}
		items := []Object{}
		for _, r := range rows {
			items = append(items, typeDict(r))
		}
		result = Object{"items": items}
		return nil
	})
	return result, e
}
func (s *Service) PutPolicy(ctx context.Context, p domain.Principal, sid, kind string, body Object) (Object, error) {
	var result Object
	e := s.WithSpace(ctx, sid, p, true, false, func(tx *store.Tx, space, member Object) error {
		if e := Require(member, "admin"); e != nil {
			return e
		}
		roles, visibility, e := validatePolicy(body)
		if e != nil {
			return e
		}
		profile, e := profiles.Get(space["profile"])
		if e != nil {
			return e
		}
		if e = profile.ValidatePolicy(kind, roles, visibility); e != nil {
			return e
		}
		policy, e := tx.One(ctx, "SELECT * FROM v2_kind_policies WHERE space_id=? AND kind=?", sid, kind)
		if e != nil {
			return e
		}
		if policy == nil {
			return domain.Err(404, "type_not_found")
		}
		if visibility == "private" {
			row, e := tx.One(ctx, "SELECT ref.name FROM v2_references ref JOIN v2_records r ON ref.space_id=r.space_id AND ref.record_id=r.id WHERE ref.space_id=? AND r.kind=? LIMIT 1", sid, kind)
			if e != nil {
				return e
			}
			if row != nil {
				return domain.Err(409, "policy_reference_conflict")
			}
		}
		if e = tx.Update(ctx, "v2_kind_policies", Object{"space_id": sid, "kind": kind}, Object{"publish_roles": roles, "visibility": visibility, "generation": num(policy["generation"]) + 1}); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "UPDATE v2_records SET shared=? WHERE space_id=? AND kind=?", visibility == "shared", sid, kind); e != nil {
			return e
		}
		if e = s.Emit(ctx, tx, sid, "policy.changed", p, nil, Object{"kind": kind}); e != nil {
			return e
		}
		result = Object{"kind": kind, "publish_roles": roles, "visibility": visibility}
		return nil
	})
	return result, e
}
