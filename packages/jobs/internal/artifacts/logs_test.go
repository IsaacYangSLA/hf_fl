//go:build linux

package artifacts

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCanonicalLogSpoolRestartDedupAndInterruptedAppend(t *testing.T) {
	root := filepath.Join(t.TempDir(), "logs")
	spool, e := NewLogSpool(root, 4096)
	if e != nil {
		t.Fatal(e)
	}
	first := "timestamp-one hello\n"
	second := first + "timestamp-two world\n"
	if e = spool.Update([]byte(first), false); e != nil {
		t.Fatal(e)
	}
	if e = spool.Update([]byte(first), false); e != nil {
		t.Fatal(e)
	}
	again, e := NewLogSpool(root, 4096)
	if e != nil {
		t.Fatal(e)
	}
	f, e := os.OpenFile(filepath.Join(root, "stdout.log"), os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	f.WriteString("uncommitted-tail")
	f.Close()
	if e = again.Update([]byte(second), true); e != nil {
		t.Fatal(e)
	}
	id := LogIdentity{"job-a", "attempt-a", "owner", 1}
	receipt, e := again.Read(id, 0, 65536)
	if e != nil || receipt.Content != second || !receipt.Complete || receipt.NextOffset != int64(len(second)) {
		t.Fatalf("%+v err=%v", receipt, e)
	}
	if e = receipt.Validate(id, 0); e != nil {
		t.Fatal(e)
	}
}
func TestCanonicalLogSpoolUTF8BoundariesRotationAndCap(t *testing.T) {
	root := filepath.Join(t.TempDir(), "logs")
	s, e := NewLogSpool(root, 256)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Update([]byte("ééé\n"), false); e != nil {
		t.Fatal(e)
	}
	id := LogIdentity{"job-a", "attempt-a", "owner", 1}
	one, e := s.Read(id, 0, 5)
	if e != nil || one.Content != "éé" || one.NextOffset != 4 {
		t.Fatalf("UTF8 %+v %v", one, e)
	}
	if _, e = s.Read(id, 1, 4); e == nil {
		t.Fatal("accepted byte inside UTF8 rune")
	}
	if e = s.Update([]byte("entirely different rotated snapshot\n"+strings.Repeat("x", 500)), true); e != nil {
		t.Fatal(e)
	}
	all, e := s.Read(id, 0, 65536)
	if e != nil || !all.Truncated || !all.Complete || len(all.Content) > 256 || !strings.Contains(all.Content, "log capture gap") || !strings.Contains(all.Content, "log output truncated") {
		t.Fatalf("cap %+v %v", all, e)
	}
}
func TestCanonicalSpoolRejectsLinkedCursorAndPrivateRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "logs")
	s, e := NewLogSpool(root, 4096)
	if e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(t.TempDir(), "foreign")
	mustWrite(t, target, []byte("{}"))
	if e = os.Symlink(target, filepath.Join(root, "cursor.json")); e != nil {
		t.Fatal(e)
	}
	if e = s.Update([]byte("text"), false); e == nil {
		t.Fatal("followed linked cursor")
	}
	os.Remove(filepath.Join(root, "cursor.json"))
	if e = os.Chmod(root, 0755); e != nil {
		t.Fatal(e)
	}
	if e = s.Update([]byte("text"), false); e == nil {
		t.Fatal("shared log root accepted")
	}
}
func TestLogIngestionDurableCursorDedupAndMonotonicOrder(t *testing.T) {
	f := newTestDB(t)
	id := LogIdentity{"job-a", "attempt-a", "owner", 1}
	source := "first\nsecond\n"
	calls := 0
	service := &LogService{DB: f.db, Clock: func() time.Time { return f.now }, ReadLogs: func(_ context.Context, identity LogIdentity, offset, maximum int64) (LogReceipt, error) {
		calls++
		content := "first\n"
		complete := false
		if offset > 0 {
			content = "second\n"
			complete = true
		}
		return LogReceipt{identity, identity.Key(), offset, offset + int64(len(content)), content, complete, false}, nil
	}}
	first, e := service.IngestComponentLogs(context.Background(), "allocation-a", false, 1)
	if e != nil || first.Bytes != 6 {
		t.Fatalf("%+v %v", first, e)
	}
	result, e := service.IngestComponentLogs(context.Background(), "allocation-a", true, 32)
	if e != nil || !result.Complete {
		t.Fatalf("%+v %v", result, e)
	}
	before := calls
	if _, e = service.IngestComponentLogs(context.Background(), "allocation-a", true, 32); e != nil || calls != before {
		t.Fatal("replayed completed source")
	}
	chunks, e := f.db.All(context.Background(), "SELECT * FROM jm_log_chunks ORDER BY created_at,id")
	if e != nil || len(chunks) != 2 {
		t.Fatalf("chunks %v %v", chunks, e)
	}
	if text(chunks[0]["data"])+text(chunks[1]["data"]) != source {
		t.Fatal("log order changed")
	}
	p := row(t, f.db, "jm_projects", "research")
	if integer(p["retained_bytes"]) != int64(len(source)) {
		t.Fatal("log quota not charged exactly once")
	}
	if !chunks[1]["created_at"].(time.Time).After(chunks[0]["created_at"].(time.Time)) {
		t.Fatal("frozen clock changed public order")
	}
	raw, _ := json.Marshal(LogReceipt{id, id.Key(), 0, 1, "x", false, false})
	if _, e = DecodeLogReceipt(raw); e != nil {
		t.Fatal(e)
	}
}

func TestLogReceiptRejectsNullOrMissingCounters(t *testing.T) {
	id := LogIdentity{"job-a", "attempt-a", "owner", 1}
	valid := map[string]any{"identity": id, "source_id": id.Key(), "offset": int64(0), "next_offset": int64(0), "content": "", "complete": false, "truncated": false}
	for _, field := range []string{"offset", "next_offset"} {
		broken := copyMap(valid)
		broken[field] = nil
		raw, _ := json.Marshal(broken)
		if _, e := DecodeLogReceipt(raw); e == nil {
			t.Fatalf("accepted null %s", field)
		}
		delete(broken, field)
		broken["unknown"] = int64(0)
		raw, _ = json.Marshal(broken)
		if _, e := DecodeLogReceipt(raw); e == nil {
			t.Fatalf("accepted missing %s", field)
		}
	}
}
