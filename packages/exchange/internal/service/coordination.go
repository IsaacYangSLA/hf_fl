package service

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/profiles"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/schema"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/store"
)

func referenceDict(row Object) Object {
	return Object{"name": row["name"], "record_id": row["record_id"], "token": strconv.FormatInt(num(row["generation"]), 10)}
}

func validateReferenceName(name string) error {
	if _, err := schema.ValidateKind(name); err != nil {
		return domain.Err(422, "invalid_reference_name")
	}
	return nil
}

func (s *Service) GetReference(ctx context.Context, p domain.Principal, sid, name string) (Object, error) {
	if err := validateReferenceName(name); err != nil {
		return nil, err
	}
	var result Object
	err := s.WithSpace(ctx, sid, p, false, false, func(tx *store.Tx, _, member Object) error {
		row, err := tx.One(ctx, "SELECT * FROM v2_references WHERE space_id=? AND name=?", sid, name)
		if err != nil {
			return err
		}
		if row == nil {
			return domain.Err(404, "reference_not_found")
		}
		if _, err = s.Record(ctx, tx, sid, str(row["record_id"]), member, p, false); err != nil {
			return err
		}
		result = referenceDict(row)
		return nil
	})
	return result, err
}

func activeAcquisition(ctx context.Context, tx *store.Tx, sid, name string) (Object, error) {
	now, err := tx.Now(ctx)
	if err != nil {
		return nil, err
	}
	return tx.One(ctx, "SELECT * FROM v2_coordinations WHERE space_id=? AND reference_name=? AND state='active' AND lease_until>?", sid, name, now)
}

func (s *Service) PutReference(ctx context.Context, p domain.Principal, sid, name string, body Object, expectedToken, key string) (Object, error) {
	if err := validateReferenceName(name); err != nil {
		return nil, err
	}
	var result Object
	err := s.WithSpace(ctx, sid, p, true, false, func(tx *store.Tx, space, member Object) error {
		if err := Require(member, "publisher"); err != nil {
			return err
		}
		var err error
		result, err = s.Once(ctx, tx, space, p, "reference.put:"+name, key, Object{"body": body, "expected_token": expectedToken}, func() (Object, error) {
			record, err := s.Record(ctx, tx, sid, str(body["record_id"]), member, p, false)
			if err != nil {
				return nil, err
			}
			if str(record["state"]) != "published" || !flag(record["shared"]) {
				return nil, domain.Err(409, "reference_requires_shared_record")
			}
			ref, err := tx.One(ctx, "SELECT * FROM v2_references WHERE space_id=? AND name=?", sid, name)
			if err != nil {
				return nil, err
			}
			if (ref == nil && expectedToken != "*") || (ref != nil && strconv.FormatInt(num(ref["generation"]), 10) != expectedToken) {
				return nil, domain.Err(412, "reference_version_mismatch")
			}
			active, err := activeAcquisition(ctx, tx, sid, name)
			if err != nil {
				return nil, err
			}
			if active != nil {
				return nil, domain.Err(409, "acquisition_active")
			}
			profile, err := profiles.Get(space["profile"])
			if err != nil {
				return nil, err
			}
			var base any
			if ref != nil {
				base = ref["record_id"]
			}
			if err = profile.ValidateReference(name, profileRecord(record), nil, base); err != nil {
				return nil, err
			}
			if ref == nil {
				ref = Object{"space_id": sid, "name": name, "record_id": record["id"], "generation": int64(1), "fence": int64(0)}
				err = tx.Insert(ctx, "v2_references", ref)
			} else {
				ref["record_id"], ref["generation"] = record["id"], num(ref["generation"])+1
				err = tx.Update(ctx, "v2_references", Object{"space_id": sid, "name": name}, Object{"record_id": ref["record_id"], "generation": ref["generation"]})
			}
			if err != nil {
				return nil, err
			}
			if err = s.Emit(ctx, tx, sid, "reference.updated", p, record["id"], Object{"name": name, "token": strconv.FormatInt(num(ref["generation"]), 10)}); err != nil {
				return nil, err
			}
			return referenceDict(ref), nil
		})
		return err
	})
	return result, err
}

func acquisitionDict(ctx context.Context, tx *store.Tx, row Object) (Object, error) {
	inputs, err := tx.All(ctx, "SELECT record_id FROM v2_coordination_inputs WHERE attempt_id=? ORDER BY record_id", row["id"])
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(inputs))
	for _, input := range inputs {
		ids = append(ids, str(input["record_id"]))
	}
	return Object{
		"id": row["id"], "reference": row["reference_name"],
		"expected_token": strconv.FormatInt(num(row["expected_generation"]), 10),
		"holder":         row["holder"], "fence": row["fence"], "state": row["state"],
		"lease_until": row["lease_until"], "input_record_ids": ids, "result_record_id": row["result_record_id"],
	}, nil
}

func acquisition(ctx context.Context, tx *store.Tx, sid, id string) (Object, error) {
	row, err := tx.One(ctx, "SELECT * FROM v2_coordinations WHERE space_id=? AND id=?", sid, id)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, domain.Err(404, "acquisition_not_found")
	}
	return row, nil
}

// participantOwners reads only the creator identities used by the frozen inputs.
// Chunking avoids parameter-count limits without weakening the command transaction.
func participantOwners(ctx context.Context, tx *store.Tx, sid string, records []Object) (map[string]Object, error) {
	unique := map[string]bool{}
	for _, record := range records {
		unique[str(record["creator"])] = true
	}
	ids := make([]string, 0, len(unique))
	for id := range unique {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := map[string]Object{}
	for start := 0; start < len(ids); start += 256 {
		end := start + 256
		if end > len(ids) {
			end = len(ids)
		}
		args := []any{sid}
		for _, id := range ids[start:end] {
			args = append(args, id)
		}
		rows, err := tx.All(ctx, "SELECT * FROM v2_members WHERE space_id=? AND principal_id IN ("+strings.TrimSuffix(strings.Repeat("?,", end-start), ",")+")", args...)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			result[str(row["principal_id"])] = row
		}
	}
	return result, nil
}

func (s *Service) Acquire(ctx context.Context, p domain.Principal, sid string, body Object, key string) (Object, error) {
	var result Object
	err := s.WithSpace(ctx, sid, p, true, false, func(tx *store.Tx, space, member Object) error {
		if err := Require(member, "publisher"); err != nil {
			return err
		}
		replayed, err := s.Once(ctx, tx, space, p, "acquisition.create", key, body, func() (Object, error) {
			name, validName := body["reference"].(string)
			if !validName {
				return nil, domain.Err(422, "invalid_reference_name")
			}
			if err := validateReferenceName(name); err != nil {
				return nil, err
			}
			ref, err := tx.One(ctx, "SELECT * FROM v2_references WHERE space_id=? AND name=?", sid, name)
			if err != nil {
				return nil, err
			}
			if ref == nil {
				return nil, domain.Err(404, "reference_not_found")
			}
			if strconv.FormatInt(num(ref["generation"]), 10) != tokenString(body["expected_token"]) {
				return nil, domain.Err(412, "reference_version_mismatch")
			}
			if _, err = s.Record(ctx, tx, sid, str(ref["record_id"]), member, p, false); err != nil {
				return nil, err
			}
			active, err := activeAcquisition(ctx, tx, sid, name)
			if err != nil {
				return nil, err
			}
			if active != nil {
				return nil, domain.Err(409, "acquisition_busy")
			}
			ids, valid := domain.Strings(get(body, "input_record_ids", []string{}))
			if !valid || len(ids) > 1000 {
				return nil, domain.Err(422, "invalid_input_records")
			}
			seen := map[string]bool{}
			for _, id := range ids {
				if seen[id] {
					return nil, domain.Err(422, "invalid_input_records")
				}
				seen[id] = true
			}
			profile, err := profiles.Get(space["profile"])
			if err != nil {
				return nil, err
			}
			if selection := profile.SelectionSpec(name, ref["record_id"]); selection != nil {
				candidates, err := tx.All(ctx, "SELECT * FROM v2_records WHERE space_id=? AND kind=? AND state='published' AND base_record_id=?", sid, selection["kind"], selection["base_id"])
				if err != nil {
					return nil, err
				}
				owners, err := participantOwners(ctx, tx, sid, candidates)
				if err != nil {
					return nil, err
				}
				eligible := make([]Object, 0, len(candidates))
				for _, record := range candidates {
					var memberView Object
					if owner := owners[str(record["creator"])]; owner != nil {
						memberView = memberDict(owner)
					}
					descriptor := profileRecord(record)
					if profile.InputEligible(descriptor, memberView) {
						eligible = append(eligible, descriptor)
					}
				}
				selected := profile.SelectInputs(eligible, ref["record_id"])
				selectedIDs := map[string]bool{}
				for _, record := range selected {
					selectedIDs[str(record["id"])] = true
				}
				for _, id := range ids {
					if !selectedIDs[id] {
						return nil, domain.Err(409, "profile_input_selection_mismatch")
					}
				}
				if len(ids) == 0 {
					ids = make([]string, 0, len(selectedIDs))
					for id := range selectedIDs {
						ids = append(ids, id)
					}
					sort.Strings(ids)
				}
				if int64(len(ids)) < num(selection["minimum"]) {
					code := str(selection["minimum_error"])
					if code == "" {
						code = "insufficient_inputs"
					}
					return nil, domain.Err(409, code)
				}
			}
			inputs := make([]Object, 0, len(ids))
			for _, id := range ids {
				record, err := s.Record(ctx, tx, sid, id, member, p, false)
				if err != nil {
					return nil, err
				}
				inputs = append(inputs, record)
			}
			for _, record := range inputs {
				if str(record["state"]) != "published" {
					return nil, domain.Err(409, "input_not_published")
				}
			}
			seconds, valid := domain.Int64(get(body, "lease_seconds", s.Settings.CoordinationSeconds))
			if !valid || seconds < 10 || seconds > 3600 {
				return nil, domain.Err(422, "invalid_lease_seconds")
			}
			if _, err = tx.Exec(ctx, "UPDATE v2_coordinations SET state='expired' WHERE space_id=? AND reference_name=? AND state='active'", sid, name); err != nil {
				return nil, err
			}
			fence := num(ref["fence"]) + 1
			if err = tx.Update(ctx, "v2_references", Object{"space_id": sid, "name": name}, Object{"fence": fence}); err != nil {
				return nil, err
			}
			now, err := tx.Now(ctx)
			if err != nil {
				return nil, err
			}
			attempt := Object{"id": domain.NewID(), "space_id": sid, "reference_name": name, "expected_generation": ref["generation"], "holder": p.ID, "fence": fence, "state": "active", "lease_until": now + float64(seconds), "created_at": now}
			if err = tx.Insert(ctx, "v2_coordinations", attempt); err != nil {
				return nil, err
			}
			for _, record := range inputs {
				if err = tx.Insert(ctx, "v2_coordination_inputs", Object{"space_id": sid, "attempt_id": attempt["id"], "record_id": record["id"]}); err != nil {
					return nil, err
				}
			}
			if err = s.Emit(ctx, tx, sid, "acquisition.started", p, nil, Object{"id": attempt["id"], "reference": name}); err != nil {
				return nil, err
			}
			return acquisitionDict(ctx, tx, attempt)
		})
		if err != nil {
			return err
		}
		row, err := acquisition(ctx, tx, sid, str(replayed["id"]))
		if err != nil {
			return err
		}
		now, err := tx.Now(ctx)
		if err != nil {
			return err
		}
		if str(row["state"]) == "active" && decimal(row["lease_until"]) <= now {
			return domain.Err(409, "acquisition_expired")
		}
		if str(row["state"]) != "active" && str(row["state"]) != "completed" {
			return domain.Err(409, "acquisition_not_active")
		}
		result, err = acquisitionDict(ctx, tx, row)
		return err
	})
	return result, err
}

// tokenString preserves the reference command's historical string comparison.
func tokenString(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	if integer, ok := domain.Integer(value); ok {
		return integer.String()
	}
	return ""
}

func (s *Service) GetAcquisition(ctx context.Context, p domain.Principal, sid, id string) (Object, error) {
	var result Object
	err := s.WithSpace(ctx, sid, p, false, false, func(tx *store.Tx, _, member Object) error {
		if err := Require(member, "publisher"); err != nil {
			return err
		}
		row, err := acquisition(ctx, tx, sid, id)
		if err != nil {
			return err
		}
		result, err = acquisitionDict(ctx, tx, row)
		return err
	})
	return result, err
}

func checkAcquisition(ctx context.Context, tx *store.Tx, row Object, p domain.Principal, fence int64) (Object, error) {
	if str(row["holder"]) != p.ID {
		return nil, domain.Err(403, "acquisition_holder_required")
	}
	ref, err := tx.One(ctx, "SELECT * FROM v2_references WHERE space_id=? AND name=?", row["space_id"], row["reference_name"])
	if err != nil {
		return nil, err
	}
	now, err := tx.Now(ctx)
	if err != nil {
		return nil, err
	}
	if str(row["state"]) != "active" || decimal(row["lease_until"]) <= now || fence != num(row["fence"]) || ref == nil || num(ref["fence"]) != fence {
		return nil, domain.Err(409, "acquisition_not_active")
	}
	return ref, nil
}

func (s *Service) Renew(ctx context.Context, p domain.Principal, sid, id string, fence int64) (Object, error) {
	var result Object
	err := s.WithSpace(ctx, sid, p, true, false, func(tx *store.Tx, _, member Object) error {
		if err := Require(member, "publisher"); err != nil {
			return err
		}
		row, err := acquisition(ctx, tx, sid, id)
		if err != nil {
			return err
		}
		if _, err = checkAcquisition(ctx, tx, row, p, fence); err != nil {
			return err
		}
		now, err := tx.Now(ctx)
		if err != nil {
			return err
		}
		row["lease_until"] = now + float64(s.Settings.CoordinationSeconds)
		if err = tx.Update(ctx, "v2_coordinations", Object{"id": id}, Object{"lease_until": row["lease_until"]}); err != nil {
			return err
		}
		result, err = acquisitionDict(ctx, tx, row)
		return err
	})
	return result, err
}

func (s *Service) Abandon(ctx context.Context, p domain.Principal, sid, id string, fence int64) (Object, error) {
	var result Object
	err := s.WithSpace(ctx, sid, p, true, false, func(tx *store.Tx, _, member Object) error {
		if err := Require(member, "publisher"); err != nil {
			return err
		}
		row, err := acquisition(ctx, tx, sid, id)
		if err != nil {
			return err
		}
		if _, err = checkAcquisition(ctx, tx, row, p, fence); err != nil {
			return err
		}
		row["state"] = "abandoned"
		if err = tx.Update(ctx, "v2_coordinations", Object{"id": id}, Object{"state": "abandoned"}); err != nil {
			return err
		}
		if err = s.Emit(ctx, tx, sid, "acquisition.abandoned", p, nil, Object{"id": id}); err != nil {
			return err
		}
		result, err = acquisitionDict(ctx, tx, row)
		return err
	})
	return result, err
}

func (s *Service) Complete(ctx context.Context, p domain.Principal, sid, id string, body Object, key string) (Object, error) {
	var result Object
	err := s.WithSpace(ctx, sid, p, true, false, func(tx *store.Tx, space, member Object) error {
		if err := Require(member, "publisher"); err != nil {
			return err
		}
		row, err := acquisition(ctx, tx, sid, id)
		if err != nil {
			return err
		}
		if str(row["holder"]) != p.ID {
			return domain.Err(403, "acquisition_holder_required")
		}
		fence, valid := domain.Int64(body["fence"])
		if str(row["state"]) == "completed" {
			if !valid || num(row["fence"]) != fence || row["result_record_id"] != body["result_record_id"] {
				return domain.Err(409, "completion_conflict")
			}
			result, err = acquisitionDict(ctx, tx, row)
			return err
		}
		result, err = s.Once(ctx, tx, space, p, "acquisition.complete:"+id, key, body, func() (Object, error) {
			if !valid {
				return nil, domain.Err(409, "acquisition_not_active")
			}
			ref, err := checkAcquisition(ctx, tx, row, p, fence)
			if err != nil {
				return nil, err
			}
			if num(ref["generation"]) != num(row["expected_generation"]) {
				return nil, domain.Err(412, "reference_version_mismatch")
			}
			record, err := s.Record(ctx, tx, sid, str(body["result_record_id"]), member, p, false)
			if err != nil {
				return nil, err
			}
			if str(record["state"]) != "published" || !flag(record["shared"]) {
				return nil, domain.Err(409, "reference_requires_shared_record")
			}
			inputRows, err := tx.All(ctx, "SELECT record_id FROM v2_coordination_inputs WHERE attempt_id=?", id)
			if err != nil {
				return nil, err
			}
			frozen := make([]Object, 0, len(inputRows))
			for _, input := range inputRows {
				inputRecord, err := s.Record(ctx, tx, sid, str(input["record_id"]), member, p, false)
				if err != nil {
					return nil, err
				}
				frozen = append(frozen, profileRecord(inputRecord))
			}
			profile, err := profiles.Get(space["profile"])
			if err != nil {
				return nil, err
			}
			used, err := profile.CompletionInputs(profileRecord(record), frozen, str(row["reference_name"]))
			if err != nil {
				return nil, err
			}
			for _, input := range used {
				if str(input["state"]) != "published" {
					return nil, domain.Err(409, "input_not_published")
				}
			}
			owners, err := participantOwners(ctx, tx, sid, used)
			if err != nil {
				return nil, err
			}
			for _, input := range used {
				var memberView Object
				if owner := owners[str(input["creator"])]; owner != nil {
					memberView = memberDict(owner)
				}
				if err = profile.ValidateInputCurrent(input, memberView); err != nil {
					return nil, err
				}
			}
			if err = profile.ValidateReference(str(row["reference_name"]), profileRecord(record), used, ref["record_id"]); err != nil {
				return nil, err
			}
			ref["record_id"], ref["generation"] = record["id"], num(ref["generation"])+1
			if err = tx.Update(ctx, "v2_references", Object{"space_id": sid, "name": ref["name"]}, Object{"record_id": record["id"], "generation": ref["generation"]}); err != nil {
				return nil, err
			}
			row["state"], row["result_record_id"] = "completed", record["id"]
			if err = tx.Update(ctx, "v2_coordinations", Object{"id": id}, Object{"state": "completed", "result_record_id": record["id"]}); err != nil {
				return nil, err
			}
			if err = s.Emit(ctx, tx, sid, "reference.updated", p, record["id"], Object{"name": ref["name"], "token": strconv.FormatInt(num(ref["generation"]), 10)}); err != nil {
				return nil, err
			}
			if err = s.Emit(ctx, tx, sid, "acquisition.completed", p, record["id"], Object{"id": id}); err != nil {
				return nil, err
			}
			return acquisitionDict(ctx, tx, row)
		})
		return err
	})
	return result, err
}
