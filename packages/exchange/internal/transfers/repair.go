package transfers

import (
	"context"
	"sort"
	"strings"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/store"
)

func validSelection(ids []string, required bool) bool {
	if (required && len(ids) == 0) || len(ids) > 100 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}
func selection(ids []string) (string, []any) {
	if len(ids) == 0 {
		return "", nil
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	return " WHERE id IN (" + strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",") + ")", args
}
func repairable(a, r Object, now float64) bool {
	markers, valid := domain.MutationTokens(a["mutation_tokens"])
	if !valid {
		return false
	}
	gateway := str(a["state"]) == "uploading" && str(r["state"]) == "draft" && len(markers) > 0
	if gateway {
		for _, token := range markers {
			if !strings.HasPrefix(token, "gateway-put-") {
				gateway = false
				break
			}
		}
	}
	state := str(a["state"])
	return (state == "cleanup" || state == "initiating" || state == "completing" || terminal(str(r["state"])) || gateway) && number(a["lease_until"]) <= now
}
func repairInventory(ctx context.Context, tx *store.Tx, ids []string) (Object, error) {
	where, args := selection(ids)
	if len(ids) == 0 {
		where = " WHERE mutation_tokens != '[]'"
	}
	rows, e := tx.All(ctx, "SELECT * FROM v2_transfer_attempts"+where+" ORDER BY id LIMIT 101", args...)
	if e != nil {
		return nil, e
	}
	now, e := tx.Now(ctx)
	if e != nil {
		return nil, e
	}
	items := []any{}
	last := len(rows)
	if last > 100 {
		last = 100
	}
	for _, a := range rows[:last] {
		b, e := tx.One(ctx, "SELECT * FROM v2_blobs WHERE id=?", a["blob_id"])
		if e != nil {
			return nil, e
		}
		if b == nil {
			return nil, domain.Err(503, "internal_transfer_error")
		}
		r, e := tx.One(ctx, "SELECT * FROM v2_records WHERE id=?", b["record_id"])
		if e != nil {
			return nil, e
		}
		if r == nil {
			return nil, domain.Err(503, "internal_transfer_error")
		}
		eligible := repairable(a, r, now)
		action := "schedule_cleanup"
		if str(r["state"]) == "draft" && str(a["state"]) == "completing" {
			action = "recover_completion"
		}
		if !eligible {
			action = "ineligible"
		}
		markers, valid := domain.MutationTokens(a["mutation_tokens"])
		var count any
		if valid {
			count = len(markers)
		}
		item := Object{"attempt_id": a["id"], "space_id": b["space_id"], "record_id": b["record_id"], "attachment_id": b["id"], "state": a["state"], "mutation_count": count, "repairable": eligible, "action": action}
		if !valid {
			item["mutation_ledger_valid"] = false
		}
		items = append(items, item)
	}
	return Object{"attempts": items, "truncated": len(rows) > 100}, nil
}

// InspectMutations returns bounded database-only inventory without private locators.
func InspectMutations(ctx context.Context, db *store.DB, ids []string) (Object, error) {
	if !validSelection(ids, false) {
		return nil, domain.Err(422, "invalid_attempt_selection")
	}
	var result Object
	e := db.WithTx(ctx, false, func(tx *store.Tx) error { var e error; result, e = repairInventory(ctx, tx, ids); return e })
	return result, e
}

// RepairMutations never calls the provider. Operators must first establish
// external quiescence; lease expiry by itself does not prove that calls stopped.
func RepairMutations(ctx context.Context, db *store.DB, ids []string, execute, writersStopped, providerQuiesced bool) (Object, error) {
	if !validSelection(ids, true) {
		return nil, domain.Err(422, "invalid_attempt_selection")
	}
	if !execute {
		return InspectMutations(ctx, db, ids)
	}
	if !writersStopped || !providerQuiesced {
		return nil, domain.Err(409, "storage_quiescence_required")
	}
	var result Object
	e := db.WithTx(ctx, true, func(tx *store.Tx) error {
		where, args := selection(ids)
		attempts, e := tx.All(ctx, "SELECT * FROM v2_transfer_attempts"+where, args...)
		if e != nil {
			return e
		}
		if len(attempts) != len(ids) {
			return domain.Err(404, "attempt_not_found")
		}
		blobs := map[string]Object{}
		spaceIDs := map[string]bool{}
		for _, a := range attempts {
			b, e := tx.One(ctx, "SELECT * FROM v2_blobs WHERE id=?", a["blob_id"])
			if e != nil {
				return e
			}
			if b == nil {
				return domain.Err(503, "internal_transfer_error")
			}
			blobs[str(b["id"])] = b
			spaceIDs[str(b["space_id"])] = true
		}
		ordered := make([]string, 0, len(spaceIDs))
		for sid := range spaceIDs {
			ordered = append(ordered, sid)
		}
		sort.Strings(ordered)
		spaces := map[string]Object{}
		for _, sid := range ordered {
			row, e := tx.One(ctx, "SELECT * FROM v2_spaces WHERE id=?"+tx.ForUpdate(), sid)
			if e != nil {
				return e
			}
			if row == nil {
				return domain.Err(503, "internal_transfer_error")
			}
			spaces[sid] = row
		}
		now, e := tx.Now(ctx)
		if e != nil {
			return e
		}
		for _, snapshot := range attempts {
			a, e := tx.One(ctx, "SELECT * FROM v2_transfer_attempts WHERE id=?"+tx.ForUpdate(), snapshot["id"])
			if e != nil {
				return e
			}
			if a == nil {
				return domain.Err(404, "attempt_not_found")
			}
			b := blobs[str(a["blob_id"])]
			if b == nil {
				return domain.Err(409, "attempt_not_repairable")
			}
			current, e := tx.One(ctx, "SELECT * FROM v2_blobs WHERE id=?", b["id"])
			if e != nil {
				return e
			}
			if current == nil {
				return domain.Err(409, "attempt_not_repairable")
			}
			b = current
			blobs[str(b["id"])] = b
			r, e := tx.One(ctx, "SELECT * FROM v2_records WHERE id=?", b["record_id"])
			if e != nil {
				return e
			}
			if r == nil || !repairable(a, r, now) {
				return domain.Err(409, "attempt_not_repairable")
			}
			recover := str(r["state"]) == "draft" && str(a["state"]) == "completing"
			a["mutation_tokens"] = []any{}
			a["token"] = nil
			a["lease_until"] = nil
			a["last_error"] = nil
			a["updated_at"] = now
			if recover {
				a["operation"] = "upload"
				a["state"] = "completing"
				a["next_attempt"] = now
			} else {
				a["operation"] = "cleanup"
				a["state"] = "cleanup"
				a["next_attempt"] = max(max(now, number(a["grant_expires_at"])), number(b["grant_expires_at"]))
			}
			if e = save(ctx, tx, "v2_transfer_attempts", a, "mutation_tokens", "operation", "state", "token", "lease_until", "next_attempt", "last_error", "updated_at"); e != nil {
				return e
			}
			if str(r["state"]) == "draft" && !recover {
				b["state"] = "reserved"
				if e = save(ctx, tx, "v2_blobs", b, "state"); e != nil {
					return e
				}
			}
			if terminal(str(r["state"])) && !flag(b["pending_deletion"]) {
				b["pending_deletion"] = true
				b["state"] = "cleanup"
				space := spaces[str(b["space_id"])]
				space["reclaiming"] = integer(space["reclaiming"]) + integer(b["size"])
				if e = save(ctx, tx, "v2_blobs", b, "pending_deletion", "state"); e != nil {
					return e
				}
				if e = save(ctx, tx, "v2_spaces", space, "reclaiming"); e != nil {
					return e
				}
			}
		}
		result, e = repairInventory(ctx, tx, ids)
		return e
	})
	return result, e
}
