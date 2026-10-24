package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/store"
)

func terminalRecordEvent(kind string) bool {
	switch kind {
	case "record.withdrawn", "record.cancelled", "record.failed", "record.expired":
		return true
	}
	return false
}

// Events applies current record, membership and policy authorization in SQL before
// pagination. Hidden history therefore neither consumes a page nor leaks counts.
func (s *Service) Events(ctx context.Context, p domain.Principal, sid string, after, limit int64) (Object, error) {
	if limit < 1 || limit > 1000 || after < 0 {
		return nil, domain.Err(422, "invalid_cursor")
	}
	var result Object
	err := s.WithSpace(ctx, sid, p, false, false, func(tx *store.Tx, space, member Object) error {
		if after < num(space["event_floor"]) {
			return domain.Err(410, "event_cursor_expired", "Reconcile current resources and resume at the supplied floor: "+fmt.Sprint(space["event_floor"]))
		}
		args := []any{sid, after}
		visible := []string{}
		if hasRole(member, "reader") || hasRole(member, "contributor") || hasRole(member, "publisher") {
			visible = append(visible, "(r.state='published' AND r.shared=?)")
			args = append(args, true)
		}
		if hasRole(member, "contributor") {
			visible = append(visible, "r.creator=?")
			args = append(args, p.ID)
		}
		if hasRole(member, "publisher") {
			visible = append(visible, "r.state='published'", "r.creator=?")
			args = append(args, p.ID)
		}
		recordVisible := "r.id='__none__'"
		if len(visible) > 0 {
			recordVisible = "(" + strings.Join(visible, " OR ") + ")"
		}
		kindExpression := "json_extract(e.payload,'$.kind')"
		publishedExpression := "json_extract(e.payload,'$.published')=1"
		if tx.Dialect == "postgresql" || tx.Dialect == "postgres" {
			kindExpression = "(e.payload->>'kind')"
			publishedExpression = "(e.payload->'published')='true'::jsonb"
		}
		tombstoneAccess := "e.type='__none__'"
		if hasRole(member, "publisher") {
			tombstoneAccess = "e.record_id IS NOT NULL"
		} else if hasRole(member, "reader") || hasRole(member, "contributor") {
			tombstoneAccess = "kp.visibility='shared'"
		}
		adminAccess := "e.type='__none__'"
		if hasRole(member, "admin") {
			adminAccess = "e.record_id IS NULL"
		}
		query := "SELECT e.* FROM v2_events e LEFT JOIN v2_records r ON r.id=e.record_id LEFT JOIN v2_kind_policies kp ON kp.space_id=e.space_id AND kp.kind=" + kindExpression +
			" WHERE e.space_id=? AND e.id>? AND ((e.record_id IS NOT NULL AND " + recordVisible + ") OR (e.type IN ('record.withdrawn','record.cancelled','record.failed','record.expired') AND " + publishedExpression + " AND " + tombstoneAccess + ") OR " + adminAccess + ") ORDER BY e.id LIMIT ?"
		args = append(args, limit+1)
		rows, err := tx.All(ctx, query, args...)
		if err != nil {
			return err
		}
		more := int64(len(rows)) > limit
		if more {
			rows = rows[:int(limit)]
		}
		cursor := after
		if more {
			cursor = num(rows[len(rows)-1]["id"])
		} else {
			last, err := tx.One(ctx, "SELECT MAX(id) AS last_id FROM v2_events WHERE space_id=?", sid)
			if err != nil {
				return err
			}
			if last != nil && num(last["last_id"]) != 0 {
				cursor = num(last["last_id"])
			}
		}
		items := make([]Object, 0, len(rows))
		for _, row := range rows {
			payload := row["payload"]
			kind := str(row["type"])
			if terminalRecordEvent(kind) {
				payload = Object{"state": strings.SplitN(kind, ".", 2)[1]}
			}
			items = append(items, Object{"id": row["id"], "type": kind, "record_id": row["record_id"], "payload": payload, "created_at": row["created_at"]})
		}
		result = Object{"items": items, "next_cursor": cursor}
		return nil
	})
	return result, err
}
