package service

import (
	"context"
	"strings"
	"testing"
)

func eventItems(t *testing.T, result Object) []Object {
	t.Helper()
	switch rows := result["items"].(type) {
	case []Object:
		return rows
	case []any:
		out := make([]Object, 0, len(rows))
		for _, row := range rows {
			out = append(out, obj(row))
		}
		return out
	default:
		t.Fatalf("items type %T", result["items"])
		return nil
	}
}
func eventIDs(rows []Object) []int64 {
	out := make([]int64, 0, len(rows))
	for _, row := range rows {
		out = append(out, num(row["id"]))
	}
	return out
}
func TestEventsCurrentVisibilityTombstonesAndCursor(t *testing.T) {
	s, p, sid := coordService(t, "generic.v1")
	ctx := context.Background()
	reader := coordMember(t, s, p, sid, strings.Repeat("b", 64), []string{"reader"}, Object{})
	admin := coordMember(t, s, p, sid, strings.Repeat("c", 64), []string{"admin"}, Object{})
	revision := coordType(t, s, p, sid, "asset")
	created, err := s.CreateRecord(ctx, p, sid, Object{"kind": "asset", "schema_revision_id": revision, "metadata": Object{"private": "draft"}, "attachments": []any{}}, "draft")
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.Events(ctx, reader, sid, 0, 1000)
	if err != nil || len(eventItems(t, before)) != 0 {
		t.Fatalf("draft leaked %v %v", before, err)
	}
	published, err := s.PublishRecord(ctx, p, sid, str(created["id"]), "publish")
	if err != nil {
		t.Fatal(err)
	}
	after, err := s.Events(ctx, reader, sid, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	items := eventItems(t, after)
	if len(items) != 2 || items[0]["type"] != "record.created" || items[1]["type"] != "record.published" {
		t.Fatalf("published content visibility %v", items)
	}
	if _, err = s.WithdrawRecord(ctx, p, sid, str(published["id"])); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PurgeRecord(ctx, p, sid, str(published["id"])); err != nil {
		t.Fatal(err)
	}
	tombstones, err := s.Events(ctx, reader, sid, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	items = eventItems(t, tombstones)
	if len(items) != 1 || items[0]["type"] != "record.withdrawn" || !equal(items[0]["payload"], Object{"state": "withdrawn"}) {
		t.Fatalf("retained minimal tombstone %v", items)
	}
	hidden, err := s.Events(ctx, admin, sid, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range eventItems(t, hidden) {
		if item["record_id"] != nil {
			t.Fatalf("admin-only gained record visibility %v", item)
		}
	}
	// A terminal event for an unpublished draft is never a public tombstone.
	draft, err := s.CreateRecord(ctx, p, sid, Object{"kind": "asset", "schema_revision_id": revision, "metadata": Object{}, "attachments": []any{}}, "unpublished")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.WithdrawRecord(ctx, p, sid, str(draft["id"])); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PurgeRecord(ctx, p, sid, str(draft["id"])); err != nil {
		t.Fatal(err)
	}
	result, err := s.Events(ctx, reader, sid, 0, 1000)
	if err != nil || len(eventItems(t, result)) != 1 {
		t.Fatalf("unpublished tombstone leaked %v %v", result, err)
	}
	maximum, err := s.DB.One(ctx, "SELECT MAX(id) AS value FROM v2_events WHERE space_id=?", sid)
	if err != nil || num(result["next_cursor"]) != num(maximum["value"]) {
		t.Fatalf("filtered events did not advance cursor %v %v", result, err)
	}
}
func TestEventsPaginationAndPolicyChanges(t *testing.T) {
	s, p, sid := coordService(t, "generic.v1")
	ctx := context.Background()
	reader := coordMember(t, s, p, sid, strings.Repeat("b", 64), []string{"reader"}, Object{})
	revision := coordType(t, s, p, sid, "asset")
	one := coordPublished(t, s, p, sid, "asset", revision, Object{"n": 1})
	coordPublished(t, s, p, sid, "asset", revision, Object{"n": 2})
	if _, err := s.PutMember(ctx, p, sid, strings.Repeat("c", 64), Object{"roles": []string{"admin"}, "bindings": Object{}}); err != nil {
		t.Fatal(err)
	}
	all, err := s.Events(ctx, reader, sid, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var pages []Object
	cursor := int64(0)
	for n := 0; n < 10; n++ {
		page, err := s.Events(ctx, reader, sid, cursor, 1)
		if err != nil {
			t.Fatal(err)
		}
		items := eventItems(t, page)
		pages = append(pages, items...)
		next := num(page["next_cursor"])
		if len(items) == 0 || next == num(all["next_cursor"]) {
			cursor = next
			break
		}
		if next <= cursor {
			t.Fatalf("cursor did not advance %v", page)
		}
		cursor = next
	}
	if !equal(eventIDs(pages), eventIDs(eventItems(t, all))) || cursor != num(all["next_cursor"]) {
		t.Fatalf("pagination %v vs %v cursors%d/%v", eventIDs(pages), eventIDs(eventItems(t, all)), cursor, all["next_cursor"])
	}
	if _, err = s.PutPolicy(ctx, p, sid, "asset", Object{"publish_roles": []string{"contributor", "publisher"}, "visibility": "private"}); err != nil {
		t.Fatal(err)
	}
	hidden, err := s.Events(ctx, reader, sid, 0, 1000)
	if err != nil || len(eventItems(t, hidden)) != 0 {
		t.Fatalf("policy revocation did not hide history %v %v", hidden, err)
	}
	if _, err = s.WithdrawRecord(ctx, p, sid, str(one["id"])); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PurgeRecord(ctx, p, sid, str(one["id"])); err != nil {
		t.Fatal(err)
	}
	hidden, err = s.Events(ctx, reader, sid, 0, 1000)
	if err != nil || len(eventItems(t, hidden)) != 0 {
		t.Fatalf("private tombstone leaked %v %v", hidden, err)
	}
	if _, err = s.PutPolicy(ctx, p, sid, "asset", Object{"publish_roles": []string{"contributor", "publisher"}, "visibility": "shared"}); err != nil {
		t.Fatal(err)
	}
	visibleAgain, err := s.Events(ctx, reader, sid, 0, 1000)
	if err != nil || len(eventItems(t, visibleAgain)) != 3 {
		t.Fatalf("current policy restoration %v %v", visibleAgain, err)
	}
	floor := num(eventItems(t, visibleAgain)[0]["id"])
	if err = s.DB.Update(ctx, "v2_spaces", Object{"id": sid}, Object{"event_floor": floor}); err != nil {
		t.Fatal(err)
	}
	_, err = s.Events(ctx, reader, sid, 0, 1000)
	coordError(t, err, "event_cursor_expired")
	if _, err = s.Events(ctx, reader, sid, floor, 1000); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ after, limit int64 }{{-1, 1}, {0, 0}, {0, 1001}} {
		_, err = s.Events(ctx, reader, sid, test.after, test.limit)
		coordError(t, err, "invalid_cursor")
	}
}
