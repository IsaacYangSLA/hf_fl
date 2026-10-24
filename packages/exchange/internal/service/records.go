package service

import (
	"context"
	"reflect"
	"strings"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/profiles"
	schema "github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/schema"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/store"
)

func (s *Service) RecordDict(ctx context.Context, tx *store.Tx, record Object, blobs []Object) (Object, error) {
	if blobs == nil {
		var e error
		blobs, e = tx.All(ctx, "SELECT * FROM v2_blobs WHERE record_id=? ORDER BY path", record["id"])
		if e != nil {
			return nil, e
		}
	}
	attachments := []Object{}
	for _, blob := range blobs {
		attachments = append(attachments, blobDict(blob))
	}
	return Object{"id": record["id"], "space_id": record["space_id"], "kind": record["kind"], "schema_revision_id": record["schema_revision_id"], "metadata": record["metadata_json"], "state": record["state"], "version": record["generation"], "shared": record["shared"], "creator": record["creator"], "creator_bindings": record["creator_bindings"], "created_at": record["created_at"], "published_at": record["published_at"], "expires_at": record["expires_at"], "attachments": attachments}, nil
}
func BlobDict(blob Object) Object { return blobDict(blob) }
func objects(v any) ([]Object, bool) {
	if v == nil {
		return nil, false
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return nil, false
	}
	out := make([]Object, 0, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		item, ok := rv.Index(i).Interface().(map[string]any)
		if !ok {
			out = append(out, nil)
		} else {
			out = append(out, item)
		}
	}
	return out, true
}
func wouldExceed(used, amount, limit int64) bool {
	return used < 0 || amount < 0 || used > limit || amount > limit-used
}

func (s *Service) CreateRecord(ctx context.Context, p domain.Principal, sid string, body Object, key string) (Object, error) {
	var result Object
	e := s.WithSpace(ctx, sid, p, true, false, func(tx *store.Tx, space, member Object) error {
		if e := Require(member, "contributor", "publisher"); e != nil {
			return e
		}
		var e error
		result, e = s.Once(ctx, tx, space, p, "record.create", key, body, func() (Object, error) {
			revision, e := tx.One(ctx, "SELECT * FROM v2_schema_revisions WHERE id=?", str(body["schema_revision_id"]))
			if e != nil {
				return nil, e
			}
			if revision == nil || str(revision["space_id"]) != sid || !equal(revision["kind"], body["kind"]) {
				return nil, domain.Err(422, "type_revision_mismatch")
			}
			policy, e := tx.One(ctx, "SELECT * FROM v2_kind_policies WHERE space_id=? AND kind=?", sid, revision["kind"])
			if e != nil {
				return nil, e
			}
			if policy == nil {
				return nil, domain.Err(422, "type_revision_mismatch")
			}
			if e = Require(member, stringsOf(policy["publish_roles"])...); e != nil {
				return nil, e
			}
			metadataValue := get(body, "metadata", Object{})
			size, e := schema.ValidateMetadata(metadataValue, obj(revision["schema"]))
			if e != nil {
				return nil, e
			}
			metadata := obj(metadataValue)
			profile, e := profiles.Get(space["profile"])
			if e != nil {
				return nil, e
			}
			if e = profile.ValidateRecord(str(revision["kind"]), metadata, obj(member["bindings"])); e != nil {
				return nil, e
			}
			attachments, ok := objects(get(body, "attachments", []Object{}))
			if !ok || len(attachments) > schema.MaxAttachments {
				return nil, domain.Err(422, "too_many_attachments")
			}
			paths := map[string]bool{}
			amount := int64(0)
			for _, attachment := range attachments {
				path, e := schema.ValidatePath(attachment["path"])
				if e != nil {
					return nil, e
				}
				fold := schema.CaseFoldPath(path)
				for existing := range paths {
					if fold == existing || strings.HasPrefix(fold, existing+"/") || strings.HasPrefix(existing, fold+"/") {
						return nil, domain.Err(422, "duplicate_attachment_path")
					}
				}
				paths[fold] = true
				length, ok := domain.Int64(attachment["size"])
				if !ok || length < 0 || length > 5*1024*1024*1024*1024 {
					return nil, domain.Err(422, "invalid_attachment_size")
				}
				digest, ok := attachment["sha256"].(string)
				if !ok || len(digest) != 64 {
					return nil, domain.Err(422, "invalid_attachment_digest")
				}
				for _, ch := range digest {
					if !strings.ContainsRune("0123456789abcdef", ch) {
						return nil, domain.Err(422, "invalid_attachment_digest")
					}
				}
				amount += length
			}
			if wouldExceed(num(space["record_count"]), 1, num(space["quota_records"])) || wouldExceed(num(space["metadata_bytes"]), size, num(space["quota_metadata_bytes"])) {
				return nil, domain.Err(409, "metadata_quota_exceeded")
			}
			if wouldExceed(num(space["allocated"]), num(space["reclaiming"]), num(space["quota_bytes"])) || wouldExceed(num(space["allocated"])+num(space["reclaiming"]), amount, num(space["quota_bytes"])) {
				return nil, domain.Err(409, "blob_quota_exceeded")
			}
			used, e := tx.One(ctx, "SELECT CAST(COALESCE(SUM(b.size),0) AS BIGINT) AS used FROM v2_blobs b JOIN v2_records r ON r.id=b.record_id WHERE r.space_id=? AND r.creator=? AND b.state<>?", sid, p.ID, "cleaned")
			if e != nil {
				return nil, e
			}
			if wouldExceed(num(used["used"]), amount, num(space["principal_quota_bytes"])) {
				return nil, domain.Err(409, "principal_blob_quota_exceeded")
			}
			now, e := tx.Now(ctx)
			if e != nil {
				return nil, e
			}
			baseID := profile.RecordBaseID(str(body["kind"]), metadata)
			if str(baseID) != "" {
				base, e := s.Record(ctx, tx, sid, str(baseID), member, p, false)
				if e != nil {
					return nil, e
				}
				if str(base["state"]) != "published" {
					return nil, domain.Err(409, "base_not_published")
				}
			}
			record := Object{"id": domain.NewID(), "space_id": sid, "kind": revision["kind"], "schema_revision_id": revision["id"], "creator": p.ID, "creator_bindings": clone(obj(member["bindings"])), "metadata_json": metadata, "metadata_bytes": size, "declared_bytes": amount, "shared": str(policy["visibility"]) == "shared", "state": "draft", "generation": int64(1), "base_record_id": baseID, "created_at": now, "published_at": nil, "expires_at": now + float64(s.Settings.DraftSeconds)}
			if e = tx.Insert(ctx, "v2_records", record); e != nil {
				return nil, e
			}
			for _, attachment := range attachments {
				length := num(attachment["size"])
				partSize := ((length + 10000*1048576 - 1) / (10000 * 1048576)) * 1048576
				if partSize < s.Settings.PartSize {
					partSize = s.Settings.PartSize
				}
				blob := Object{"id": domain.NewID(), "space_id": sid, "record_id": record["id"], "path": attachment["path"], "size": attachment["size"], "sha256": attachment["sha256"], "media_type": get(attachment, "media_type", "application/octet-stream"), "state": "reserved", "part_size": partSize, "expires_at": record["expires_at"]}
				if e = tx.Insert(ctx, "v2_blobs", blob); e != nil {
					return nil, e
				}
			}
			if e = update(ctx, tx, "v2_spaces", Object{"id": sid}, space, Object{"record_count": num(space["record_count"]) + 1, "metadata_bytes": num(space["metadata_bytes"]) + size, "allocated": num(space["allocated"]) + amount}); e != nil {
				return nil, e
			}
			if e = s.Emit(ctx, tx, sid, "record.created", p, record["id"], nil); e != nil {
				return nil, e
			}
			return s.RecordDict(ctx, tx, record, nil)
		})
		return e
	})
	return result, e
}
func (s *Service) GetRecord(ctx context.Context, p domain.Principal, sid, rid string) (Object, error) {
	var result Object
	e := s.WithSpace(ctx, sid, p, false, false, func(tx *store.Tx, _ Object, member Object) error {
		record, e := s.Record(ctx, tx, sid, rid, member, p, false)
		if e != nil {
			return e
		}
		result, e = s.RecordDict(ctx, tx, record, nil)
		return e
	})
	return result, e
}
func visibleSQL(member Object, p domain.Principal, alias string) (string, []any) {
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	clauses := []string{}
	args := []any{}
	if hasRole(member, "reader") || hasRole(member, "contributor") || hasRole(member, "publisher") {
		clauses = append(clauses, "("+prefix+"state=? AND "+prefix+"shared=?)")
		args = append(args, "published", true)
	}
	if hasRole(member, "contributor") {
		clauses = append(clauses, prefix+"creator=?")
		args = append(args, p.ID)
	}
	if hasRole(member, "publisher") {
		clauses = append(clauses, "("+prefix+"state=? OR "+prefix+"creator=?)")
		args = append(args, "published", p.ID)
	}
	if len(clauses) == 0 {
		return prefix + "id=?", []any{"__none__"}
	}
	return "(" + strings.Join(clauses, " OR ") + ")", args
}
func (s *Service) ListRecords(ctx context.Context, p domain.Principal, sid, kind, after string, limit int64, state string) (Object, error) {
	if limit < 1 || limit > 1000 {
		return nil, domain.Err(422, "invalid_limit")
	}
	var result Object
	e := s.WithSpace(ctx, sid, p, false, false, func(tx *store.Tx, _ Object, member Object) error {
		clause, visibleArgs := visibleSQL(member, p, "")
		query := "SELECT * FROM v2_records WHERE space_id=? AND " + clause
		args := []any{sid}
		args = append(args, visibleArgs...)
		if kind != "" {
			query += " AND kind=?"
			args = append(args, kind)
		}
		if state != "" {
			query += " AND state=?"
			args = append(args, state)
		}
		if after != "" {
			query += " AND id>?"
			args = append(args, after)
		}
		query += " ORDER BY id LIMIT ?"
		args = append(args, limit+1)
		rows, e := tx.All(ctx, query, args...)
		if e != nil {
			return e
		}
		more := int64(len(rows)) > limit
		if more {
			rows = rows[:limit]
		}
		grouped := map[string][]Object{}
		ids := []any{}
		for _, record := range rows {
			grouped[str(record["id"])] = []Object{}
			ids = append(ids, record["id"])
		}
		if len(ids) > 0 {
			marks := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
			blobs, e := tx.All(ctx, "SELECT * FROM v2_blobs WHERE record_id IN ("+marks+") ORDER BY path", ids...)
			if e != nil {
				return e
			}
			for _, blob := range blobs {
				id := str(blob["record_id"])
				grouped[id] = append(grouped[id], blob)
			}
		}
		items := []Object{}
		for _, record := range rows {
			item, e := s.RecordDict(ctx, tx, record, grouped[str(record["id"])])
			if e != nil {
				return e
			}
			items = append(items, item)
		}
		var cursor any
		if more {
			cursor = rows[len(rows)-1]["id"]
		}
		result = Object{"items": items, "next_cursor": cursor}
		return nil
	})
	return result, e
}
func (s *Service) PatchRecord(ctx context.Context, p domain.Principal, sid, rid string, body Object, expectedVersion string) (Object, error) {
	var result Object
	e := s.WithSpace(ctx, sid, p, true, false, func(tx *store.Tx, space, member Object) error {
		record, e := s.Record(ctx, tx, sid, rid, member, p, true)
		if e != nil {
			return e
		}
		if e = s.CheckDraft(ctx, tx, record); e != nil {
			return e
		}
		if str(record["generation"]) != expectedVersion {
			return domain.Err(412, "record_version_mismatch")
		}
		revision, e := tx.One(ctx, "SELECT * FROM v2_schema_revisions WHERE id=?", record["schema_revision_id"])
		if e != nil {
			return e
		}
		metadata := obj(body["metadata"])
		size, e := schema.ValidateMetadata(body["metadata"], obj(revision["schema"]))
		if e != nil {
			return e
		}
		profile, e := profiles.Get(space["profile"])
		if e != nil {
			return e
		}
		if e = profile.ValidateRecord(str(record["kind"]), metadata, obj(record["creator_bindings"])); e != nil {
			return e
		}
		baseUsage := num(space["metadata_bytes"]) - num(record["metadata_bytes"])
		if wouldExceed(baseUsage, size, num(space["quota_metadata_bytes"])) {
			return domain.Err(409, "metadata_quota_exceeded")
		}
		baseID := profile.RecordBaseID(str(record["kind"]), metadata)
		if str(baseID) != "" {
			if _, e = s.Record(ctx, tx, sid, str(baseID), member, p, false); e != nil {
				return e
			}
		}
		if e = update(ctx, tx, "v2_spaces", Object{"id": sid}, space, Object{"metadata_bytes": baseUsage + size}); e != nil {
			return e
		}
		if e = update(ctx, tx, "v2_records", Object{"id": rid}, record, Object{"metadata_json": metadata, "metadata_bytes": size, "base_record_id": baseID, "generation": num(record["generation"]) + 1}); e != nil {
			return e
		}
		if e = s.Emit(ctx, tx, sid, "record.updated", p, rid, nil); e != nil {
			return e
		}
		result, e = s.RecordDict(ctx, tx, record, nil)
		return e
	})
	return result, e
}
func (s *Service) PublishRecord(ctx context.Context, p domain.Principal, sid, rid, key string) (Object, error) {
	var result Object
	e := s.WithSpace(ctx, sid, p, true, false, func(tx *store.Tx, space, member Object) error {
		record, e := s.Record(ctx, tx, sid, rid, member, p, true)
		if e != nil {
			return e
		}
		policy, e := tx.One(ctx, "SELECT * FROM v2_kind_policies WHERE space_id=? AND kind=?", sid, record["kind"])
		if e != nil {
			return e
		}
		if policy == nil {
			return domain.Err(404, "type_not_found")
		}
		if e = Require(member, stringsOf(policy["publish_roles"])...); e != nil {
			return e
		}
		result, e = s.Once(ctx, tx, space, p, "record.publish:"+rid, key, Object{}, func() (Object, error) {
			if e := s.CheckDraft(ctx, tx, record); e != nil {
				return nil, e
			}
			revision, e := tx.One(ctx, "SELECT * FROM v2_schema_revisions WHERE id=?", record["schema_revision_id"])
			if e != nil {
				return nil, e
			}
			if _, e = schema.ValidateMetadata(record["metadata_json"], obj(revision["schema"])); e != nil {
				return nil, e
			}
			profile, e := profiles.Get(space["profile"])
			if e != nil {
				return nil, e
			}
			if e = profile.ValidatePublish(str(record["kind"]), obj(record["metadata_json"]), obj(record["creator_bindings"]), obj(member["bindings"])); e != nil {
				return nil, e
			}
			if str(record["base_record_id"]) != "" {
				base, e := s.Record(ctx, tx, sid, str(record["base_record_id"]), member, p, false)
				if e != nil {
					return nil, e
				}
				if str(base["state"]) != "published" {
					return nil, domain.Err(409, "base_not_published")
				}
			}
			blobs, e := tx.All(ctx, "SELECT * FROM v2_blobs WHERE record_id=?", rid)
			if e != nil {
				return nil, e
			}
			for _, blob := range blobs {
				if str(blob["state"]) != "verified" || str(blob["object_version"]) == "" || !equal(blob["verified_size"], blob["size"]) || !equal(blob["verified_sha256"], blob["sha256"]) {
					return nil, domain.Err(409, "attachments_not_verified")
				}
			}
			now, e := tx.Now(ctx)
			if e != nil {
				return nil, e
			}
			if e = update(ctx, tx, "v2_records", Object{"id": rid}, record, Object{"state": "published", "published_at": now, "shared": str(policy["visibility"]) == "shared", "generation": num(record["generation"]) + 1}); e != nil {
				return nil, e
			}
			if e = s.Emit(ctx, tx, sid, "record.published", p, rid, nil); e != nil {
				return nil, e
			}
			return s.RecordDict(ctx, tx, record, blobs)
		})
		return e
	})
	return result, e
}
func (s *Service) ReleaseRecord(ctx context.Context, tx *store.Tx, space, record Object, state string) error {
	if terminalStates[str(record["state"])] {
		return nil
	}
	sid := str(space["id"])
	rid := str(record["id"])
	if e := update(ctx, tx, "v2_records", Object{"id": rid}, record, Object{"state": state, "generation": num(record["generation"]) + 1}); e != nil {
		return e
	}
	allocated := num(space["allocated"]) - num(record["declared_bytes"])
	reclaiming := num(space["reclaiming"])
	now, e := tx.Now(ctx)
	if e != nil {
		return e
	}
	blobs, e := tx.All(ctx, "SELECT * FROM v2_blobs WHERE record_id=?", rid)
	if e != nil {
		return e
	}
	for _, blob := range blobs {
		if flag(blob["pending_deletion"]) {
			continue
		}
		attempts, e := tx.All(ctx, "SELECT * FROM v2_transfer_attempts WHERE blob_id=?", blob["id"])
		if e != nil {
			return e
		}
		allCleaned := true
		for _, attempt := range attempts {
			if str(attempt["state"]) != "cleaned" || mutationTokensPending(attempt["mutation_tokens"]) {
				allCleaned = false
				break
			}
		}
		if allCleaned {
			// Prior cleanup positively proved every owned attempt absent. A draft
			// may remain reusable after that cleanup; terminalization can now
			// discard the reservation without inventing a new cleanup task.
			if e = tx.Update(ctx, "v2_blobs", Object{"id": blob["id"]}, Object{"state": "cleaned"}); e != nil {
				return e
			}
			continue
		}
		reclaiming += num(blob["size"])
		expires := now
		if decimal(blob["grant_expires_at"]) > expires {
			expires = decimal(blob["grant_expires_at"])
		}
		blobValues := Object{"pending_deletion": true, "expires_at": expires}
		if str(blob["state"]) == "cleaned" {
			// A retained marker contradicts a cleaned label. Preserve the charge
			// and put that attempt back behind the normal quiescence barrier.
			blobValues["state"] = "cleanup"
		}
		if e = tx.Update(ctx, "v2_blobs", Object{"id": blob["id"]}, blobValues); e != nil {
			return e
		}
		for _, attempt := range attempts {
			if str(attempt["state"]) == "cleaned" && !mutationTokensPending(attempt["mutation_tokens"]) {
				continue
			}
			next := expires
			if decimal(attempt["grant_expires_at"]) > next {
				next = decimal(attempt["grant_expires_at"])
			}
			if e = tx.Update(ctx, "v2_transfer_attempts", Object{"id": attempt["id"]}, Object{"state": "cleanup", "operation": "cleanup", "next_attempt": next}); e != nil {
				return e
			}
		}
	}
	if e = update(ctx, tx, "v2_spaces", Object{"id": sid}, space, Object{"allocated": allocated, "reclaiming": reclaiming}); e != nil {
		return e
	}
	return s.Emit(ctx, tx, sid, "record."+state, domain.Principal{ID: "system"}, rid, Object{"state": state, "kind": record["kind"], "published": record["published_at"] != nil})
}
func (s *Service) WithdrawRecord(ctx context.Context, p domain.Principal, sid, rid string) (Object, error) {
	var result Object
	e := s.WithSpace(ctx, sid, p, true, false, func(tx *store.Tx, space, member Object) error {
		var record Object
		var e error
		if hasRole(member, "admin") {
			record, e = tx.One(ctx, "SELECT * FROM v2_records WHERE space_id=? AND id=?", sid, rid)
			if e != nil {
				return e
			}
			if record == nil {
				return domain.Err(404, "record_not_found")
			}
		} else {
			record, e = s.Record(ctx, tx, sid, rid, member, p, true)
			if e != nil {
				return e
			}
		}
		child, e := tx.One(ctx, "SELECT id FROM v2_records WHERE space_id=? AND base_record_id=? AND state=? LIMIT 1", sid, rid, "published")
		if e != nil {
			return e
		}
		if child != nil {
			return domain.Err(409, "record_retained_for_provenance")
		}
		reference, e := tx.One(ctx, "SELECT name FROM v2_references WHERE space_id=? AND record_id=? LIMIT 1", sid, rid)
		if e != nil {
			return e
		}
		if reference != nil {
			return domain.Err(409, "record_referenced")
		}
		now, e := tx.Now(ctx)
		if e != nil {
			return e
		}
		busy, e := tx.One(ctx, "SELECT c.id FROM v2_coordinations c JOIN v2_coordination_inputs i ON i.attempt_id=c.id WHERE c.space_id=? AND c.state=? AND c.lease_until>? AND i.record_id=? LIMIT 1", sid, "active", now, rid)
		if e != nil {
			return e
		}
		if busy != nil {
			return domain.Err(409, "record_in_active_acquisition")
		}
		state := "cancelled"
		if str(record["state"]) == "published" {
			state = "withdrawn"
		}
		if e = s.ReleaseRecord(ctx, tx, space, record, state); e != nil {
			return e
		}
		result = Object{"id": rid, "state": record["state"]}
		return nil
	})
	return result, e
}
func (s *Service) PurgeRecord(ctx context.Context, p domain.Principal, sid, rid string) (Object, error) {
	var result Object
	e := s.WithSpace(ctx, sid, p, true, false, func(tx *store.Tx, space, member Object) error {
		if e := Require(member, "admin"); e != nil {
			return e
		}
		record, e := tx.One(ctx, "SELECT * FROM v2_records WHERE space_id=? AND id=?", sid, rid)
		if e != nil {
			return e
		}
		if record == nil {
			return domain.Err(404, "record_not_found")
		}
		if !terminalStates[str(record["state"])] {
			return domain.Err(409, "record_not_terminal")
		}
		blobs, e := tx.All(ctx, "SELECT * FROM v2_blobs WHERE record_id=?", rid)
		if e != nil {
			return e
		}
		for _, blob := range blobs {
			if str(blob["state"]) != "cleaned" {
				return domain.Err(409, "cleanup_pending")
			}
		}
		attempts, e := tx.All(ctx, "SELECT a.* FROM v2_transfer_attempts a JOIN v2_blobs b ON b.id=a.blob_id WHERE b.record_id=?", rid)
		if e != nil {
			return e
		}
		for _, attempt := range attempts {
			if mutationTokensPending(attempt["mutation_tokens"]) {
				return domain.Err(409, "cleanup_pending")
			}
		}
		queries := []string{"SELECT attempt_id AS id FROM v2_coordination_inputs WHERE record_id=? LIMIT 1", "SELECT id FROM v2_records WHERE space_id=? AND base_record_id=? LIMIT 1", "SELECT id FROM v2_coordinations WHERE result_record_id=? LIMIT 1"}
		for i, query := range queries {
			args := []any{rid}
			if i == 1 {
				args = []any{sid, rid}
			}
			row, e := tx.One(ctx, query, args...)
			if e != nil {
				return e
			}
			if row != nil {
				return domain.Err(409, "record_retained_for_provenance")
			}
		}
		if _, e = tx.Exec(ctx, "DELETE FROM v2_transfer_attempts WHERE blob_id IN (SELECT id FROM v2_blobs WHERE record_id=?)", rid); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "DELETE FROM v2_blobs WHERE record_id=?", rid); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "DELETE FROM v2_events WHERE record_id=? AND type NOT IN (?,?,?,?)", rid, "record.withdrawn", "record.cancelled", "record.failed", "record.expired"); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "DELETE FROM v2_records WHERE id=?", rid); e != nil {
			return e
		}
		if e = update(ctx, tx, "v2_spaces", Object{"id": sid}, space, Object{"record_count": num(space["record_count"]) - 1, "metadata_bytes": num(space["metadata_bytes"]) - num(record["metadata_bytes"])}); e != nil {
			return e
		}
		if e = s.Emit(ctx, tx, sid, "record.purged", p, nil, Object{"record_id": rid}); e != nil {
			return e
		}
		result = Object{"id": rid, "state": "purged"}
		return nil
	})
	return result, e
}
