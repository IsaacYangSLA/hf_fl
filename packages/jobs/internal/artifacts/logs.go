//go:build linux

package artifacts

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
	"golang.org/x/sys/unix"
)

const MaxLogChunkBytes int64 = 65536
const MaxCanonicalLogBytes int64 = 1 << 20
const logGap = "\n[log capture gap: earlier rotated output unavailable]\n"
const logLimit = "\n[log output truncated at the execution log limit]\n"

func storedCount(m map[string]any, key string, fallback int64) int64 {
	v, exists := m[key]
	if !exists {
		return fallback
	}
	if v == nil {
		return -1
	}
	return integer(v)
}

func utf8Prefix(raw []byte, maximum int64) string {
	if maximum < 0 {
		return ""
	}
	if int64(len(raw)) > maximum {
		raw = raw[:maximum]
	}
	for len(raw) > 0 && !utf8.Valid(raw) {
		raw = raw[:len(raw)-1]
	}
	return string(raw)
}
func (c *SafeCollector) Redact(value string, maxBytes int64) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if maxBytes < 0 || !utf8.ValidString(value) {
		return "", collectionError("invalid_log_text")
	}
	return c.redact(value, maxBytes)
}

type LogIdentity struct {
	JobID       string `json:"job_id"`
	AttemptID   string `json:"attempt_id"`
	ComponentID string `json:"component_id"`
	Epoch       int64  `json:"epoch"`
}

func (i LogIdentity) Validate() error {
	for _, id := range []string{i.JobID, i.AttemptID, i.ComponentID} {
		if err := domain.ValidateIdentifier(id); err != nil {
			return domain.Err(422, "invalid_log_identity")
		}
	}
	if i.Epoch < 1 {
		return domain.Err(422, "invalid_log_identity")
	}
	return nil
}
func (i LogIdentity) Key() string {
	raw, err := domain.CanonicalJSON(map[string]any{"job_id": i.JobID, "attempt_id": i.AttemptID, "component_id": i.ComponentID, "epoch": i.Epoch})
	if err != nil {
		return ""
	}
	return digest(raw)[:32]
}

type LogReceipt struct {
	Identity   LogIdentity `json:"identity"`
	SourceID   string      `json:"source_id"`
	Offset     int64       `json:"offset"`
	NextOffset int64       `json:"next_offset"`
	Content    string      `json:"content"`
	Complete   bool        `json:"complete"`
	Truncated  bool        `json:"truncated"`
}

func (r LogReceipt) Validate(identity LogIdentity, offset int64) error {
	if err := identity.Validate(); err != nil {
		return err
	}
	if r.Identity != identity || r.SourceID != identity.Key() || r.Offset != offset || offset < 0 || r.NextOffset != offset+int64(len(r.Content)) || r.NextOffset > MaxCanonicalLogBytes || int64(len(r.Content)) > MaxLogChunkBytes || !utf8.ValidString(r.Content) {
		return domain.Err(422, "invalid_log_receipt")
	}
	return nil
}

type CanonicalLogSpool struct {
	mu      sync.Mutex
	root    string
	maximum int64
}

func NewLogSpool(root string, maxBytes int64) (*CanonicalLogSpool, error) {
	if maxBytes == 0 {
		maxBytes = MaxCanonicalLogBytes - MaxLogChunkBytes
	}
	if maxBytes < 256 || maxBytes > MaxCanonicalLogBytes {
		return nil, domain.Err(422, "invalid_log_bound")
	}
	fd, err := openAbsolute(root, true, nil)
	if err != nil {
		return nil, domain.Err(409, "unsafe_log_root")
	}
	defer unix.Close(fd)
	if err = privateDirectory(fd); err != nil {
		return nil, domain.Err(409, "unsafe_log_root")
	}
	return &CanonicalLogSpool{root: root, maximum: maxBytes}, nil
}
func (s *CanonicalLogSpool) directory() (int, error) {
	fd, err := openAbsolute(s.root, false, nil)
	if err != nil {
		return -1, domain.Err(409, "unsafe_log_root")
	}
	if err = privateDirectory(fd); err != nil {
		unix.Close(fd)
		return -1, domain.Err(409, "unsafe_log_root")
	}
	return fd, nil
}
func spoolFile(directory int, name string, flags int, maximum int64) (int, error) {
	fd, err := unix.Openat(directory, name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Getuid()) || st.Mode&0077 != 0 || st.Size > maximum {
		unix.Close(fd)
		return -1, domain.Err(409, "unsafe_log_file")
	}
	return fd, nil
}
func spoolMetadata(directory int) (map[string]any, error) {
	fd, err := spoolFile(directory, "cursor.json", unix.O_RDONLY, 32768)
	if errors.Is(err, unix.ENOENT) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "cursor.json")
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 32769))
	if err != nil || len(raw) > 32768 {
		return nil, domain.Err(409, "unsafe_log_file")
	}
	value, err := domain.DecodeJSON(raw)
	if err != nil {
		return nil, domain.Err(409, "unsafe_log_file")
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, domain.Err(409, "unsafe_log_file")
	}
	return m, nil
}
func spoolSave(directory int, data map[string]any) error {
	raw, err := domain.CanonicalJSON(data)
	if err != nil || len(raw) > 32768 {
		return domain.Err(409, "unsafe_log_file")
	}
	if err = unix.Unlinkat(directory, "cursor.pending", 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	fd, err := spoolFile(directory, "cursor.pending", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 32768)
	if err != nil {
		return err
	}
	if err = writeAll(fd, raw); err == nil {
		err = unix.Fsync(fd)
	}
	unix.Close(fd)
	if err != nil {
		return err
	}
	if err = unix.Renameat(directory, "cursor.pending", directory, "cursor.json"); err != nil {
		return err
	}
	return unix.Fsync(directory)
}
func (s *CanonicalLogSpool) Update(redactedSnapshot []byte, complete bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot := []byte(strings.ToValidUTF8(string(redactedSnapshot), "\uFFFD"))
	if len(snapshot) > 4<<20 {
		return domain.Err(422, "log_snapshot_exceeds_bound")
	}
	directory, err := s.directory()
	if err != nil {
		return err
	}
	defer unix.Close(directory)
	if err = unix.Flock(directory, unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(directory, unix.LOCK_UN)
	metadata, err := spoolMetadata(directory)
	if err != nil {
		return err
	}
	fd, err := spoolFile(directory, "stdout.log", unix.O_WRONLY|unix.O_CREAT|unix.O_APPEND, s.maximum)
	if err != nil {
		return err
	}
	err = func() error {
		defer unix.Close(fd)
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return err
		}
		committed := storedCount(metadata, "length", 0)
		if committed < 0 || committed > st.Size {
			return domain.Err(409, "unsafe_log_file")
		}
		if st.Size != committed {
			if err := unix.Ftruncate(fd, committed); err != nil {
				return err
			}
		}
		hash := digest(snapshot)
		addition := []byte{}
		truncated := flag(metadata["truncated"])
		limited := flag(metadata["limited"])
		if text(metadata["snapshot_sha256"]) != hash && !limited {
			previousLength := integer(metadata["snapshot_length"])
			previous := text(metadata["snapshot_sha256"])
			if previous != "" && previousLength >= 0 && previousLength <= int64(len(snapshot)) && digest(snapshot[:previousLength]) == previous {
				addition = snapshot[previousLength:]
			} else if previous != "" {
				anchor := text(metadata["snapshot_anchor"])
				entryLength := integer(metadata["snapshot_entry_length"])
				index := -1
				if anchor != "" {
					index = strings.LastIndex(string(snapshot), anchor)
				}
				if index >= 0 && entryLength > 0 && int64(index)+entryLength <= int64(len(snapshot)) && digest(snapshot[index:int64(index)+entryLength]) == text(metadata["snapshot_entry_sha256"]) {
					addition = snapshot[int64(index)+entryLength:]
				} else {
					addition = append([]byte(logGap), snapshot...)
					truncated = true
				}
			} else {
				addition = snapshot
			}
		}
		room := s.maximum - committed
		if int64(len(addition)) > room {
			limited = true
			truncated = true
			prefixRoom := room - int64(len(logLimit))
			if prefixRoom < 0 {
				prefixRoom = 0
			}
			addition = []byte(utf8Prefix(addition, prefixRoom))
			if room-int64(len(addition)) >= int64(len(logLimit)) {
				addition = append(addition, []byte(logLimit)...)
			}
		}
		if len(addition) > 0 {
			if err := writeAll(fd, addition); err != nil {
				return err
			}
			if err := unix.Fsync(fd); err != nil {
				return err
			}
		}
		trimmed := strings.TrimRight(string(snapshot), "\n")
		lastStart := strings.LastIndex(trimmed, "\n") + 1
		last := snapshot[lastStart:]
		anchor := utf8Prefix(last, 256)
		metadata = map[string]any{"length": committed + int64(len(addition)), "snapshot_sha256": hash, "snapshot_length": int64(len(snapshot)), "snapshot_anchor": anchor, "snapshot_entry_length": int64(len(last)), "snapshot_entry_sha256": digest(last), "complete": complete || flag(metadata["complete"]), "truncated": truncated, "limited": limited}
		return nil
	}()
	if err != nil {
		return err
	}
	return spoolSave(directory, metadata)
}
func (s *CanonicalLogSpool) MarkComplete() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.directory()
	if err != nil {
		return err
	}
	defer unix.Close(d)
	if err = unix.Flock(d, unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(d, unix.LOCK_UN)
	m, err := spoolMetadata(d)
	if err != nil {
		return err
	}
	m["complete"] = true
	if _, exists := m["length"]; !exists {
		m["length"] = int64(0)
	}
	return spoolSave(d, m)
}
func (s *CanonicalLogSpool) Read(identity LogIdentity, offset, maxBytes int64) (LogReceipt, error) {
	empty := LogReceipt{}
	if err := identity.Validate(); err != nil {
		return empty, err
	}
	if offset < 0 || maxBytes < 4 || maxBytes > MaxLogChunkBytes {
		return empty, domain.Err(422, "invalid_log_cursor")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.directory()
	if err != nil {
		return empty, err
	}
	defer unix.Close(d)
	if err = unix.Flock(d, unix.LOCK_SH); err != nil {
		return empty, err
	}
	defer unix.Flock(d, unix.LOCK_UN)
	m, err := spoolMetadata(d)
	if err != nil {
		return empty, err
	}
	length := storedCount(m, "length", 0)
	if length < 0 || length > s.maximum || offset > length {
		return empty, domain.Err(409, "log_cursor_conflict")
	}
	size := min64(maxBytes, length-offset)
	raw := make([]byte, size)
	fd, err := spoolFile(d, "stdout.log", unix.O_RDONLY, s.maximum)
	if errors.Is(err, unix.ENOENT) && length == 0 {
		raw = []byte{}
	} else if err != nil {
		return empty, domain.Err(409, "unsafe_log_file")
	} else {
		count, e := unix.Pread(fd, raw, offset)
		unix.Close(fd)
		if e != nil || int64(count) != size {
			return empty, domain.Err(409, "unsafe_log_file")
		}
	}
	for index := 0; index < len(raw); {
		_, size := utf8.DecodeRune(raw[index:])
		if size == 1 && raw[index] >= utf8.RuneSelf {
			if !utf8.FullRune(raw[index:]) {
				raw = raw[:index]
				break
			}
			return empty, domain.Err(409, "log_cursor_conflict")
		}
		index += size
	}
	next := offset + int64(len(raw))
	return LogReceipt{identity, identity.Key(), offset, next, string(raw), flag(m["complete"]) && next == length, flag(m["truncated"])}, nil
}

type LogIngestResult struct {
	Status    string `json:"status"`
	Chunks    int    `json:"chunks"`
	Bytes     int64  `json:"bytes"`
	Complete  bool   `json:"complete"`
	Truncated bool   `json:"truncated"`
}
type LogReader func(context.Context, LogIdentity, int64, int64) (LogReceipt, error)
type LogService struct {
	DB       *store.DB
	Clock    func() time.Time
	ReadLogs LogReader
}

func (s *LogService) now() time.Time {
	if s.Clock != nil {
		return s.Clock().UTC()
	}
	return time.Now().UTC()
}
func logsExpired(job map[string]any, now time.Time) bool {
	if job == nil || job["purged_at"] != nil {
		return true
	}
	switch text(job["cleanup_status"]) {
	case "purge_pending", "expiry_pending", "expired":
		return true
	}
	expiry, has := store.Time(job["artifacts_expire_at"])
	return has && !expiry.After(now)
}
func ownedLogBudget(ctx context.Context, tx *store.Tx, holder, job, attempt map[string]any) (map[string]any, error) {
	d := mapping(holder["details_json"])
	raw, exists := d["log_resource_id"]
	if !exists || raw == nil {
		return nil, nil
	}
	id := text(raw)
	if id == "" {
		return nil, domain.Err(409, "retained_log_budget_ownership_mismatch")
	}
	b, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id = ?"+tx.ForUpdate(), id)
	if e != nil {
		return nil, e
	}
	if b == nil {
		return nil, domain.Err(409, "retained_log_budget_ownership_mismatch")
	}
	bd := mapping(b["details_json"])
	own := mapping(b["ownership_json"])
	expected := "hf2l-log://" + text(job["id"]) + "/" + strconv.FormatInt(integer(attempt["number"]), 10) + "/" + text(holder["component_id"])
	if text(b["kind"]) != "log_budget" || b["job_id"] != job["id"] || b["attempt_id"] != attempt["id"] || b["component_id"] != holder["component_id"] || text(b["external_id"]) != expected || own["job_id"] != job["id"] || own["component_id"] != holder["component_id"] || text(own["kind"]) != "log_budget" || integer(bd["attempt_number"]) != integer(attempt["number"]) || bd["component_id"] != holder["component_id"] {
		return nil, domain.Err(409, "retained_log_budget_ownership_mismatch")
	}
	return b, nil
}
func logStamp(ctx context.Context, tx *store.Tx, jobID string, now time.Time) (time.Time, error) {
	row, e := tx.One(ctx, "SELECT MAX(created_at) AS created_at FROM jm_log_chunks WHERE job_id = ?", jobID)
	if e != nil {
		return time.Time{}, e
	}
	if previous, ok := store.Time(row["created_at"]); ok && !now.After(previous) {
		now = previous.Add(time.Microsecond)
	}
	return now, nil
}
func appendLogInTx(ctx context.Context, tx *store.Tx, project, job, attempt, holder map[string]any, content string, now time.Time) (int64, error) {
	budget, e := ownedLogBudget(ctx, tx, holder, job, attempt)
	if e != nil {
		return 0, e
	}
	row, e := tx.One(ctx, "SELECT COALESCE(MAX(sequence),0) AS sequence FROM jm_log_chunks WHERE job_id = ? AND component = ?", job["id"], holder["component_id"])
	if e != nil {
		return 0, e
	}
	created, e := logStamp(ctx, tx, text(job["id"]), now)
	if e != nil {
		return 0, e
	}
	chunk := map[string]any{"id": domain.NewID(), "job_id": job["id"], "attempt_number": attempt["number"], "component": holder["component_id"], "sequence": integer(row["sequence"]) + 1, "data": content, "charged_bytes": int64(0), "created_at": created, "expires_at": job["artifacts_expire_at"]}
	if _, e = ChargeLogInTransaction(ctx, tx, project, chunk, budget); e != nil {
		return 0, e
	}
	if e = tx.Insert(ctx, "jm_log_chunks", chunk); e != nil {
		return 0, e
	}
	return int64(len(text(chunk["data"]))), nil
}
func (s *LogService) IngestComponentLogs(ctx context.Context, allocationID string, terminal bool, maxChunks int) (LogIngestResult, error) {
	result := LogIngestResult{Status: "unavailable"}
	if maxChunks < 1 || maxChunks > 32 {
		return result, domain.Err(422, "invalid_log_bound")
	}
	if s.ReadLogs == nil {
		return result, nil
	}
	exhausted := false
	for iteration := 0; iteration < maxChunks; iteration++ {
		var allocation, job map[string]any
		var identity LogIdentity
		var offset int64
		e := s.DB.WithTx(ctx, false, func(tx *store.Tx) error {
			var err error
			allocation, err = tx.One(ctx, "SELECT * FROM jm_allocations WHERE id = ?", allocationID)
			if err != nil || allocation == nil {
				return err
			}
			job, err = tx.One(ctx, "SELECT * FROM jm_jobs WHERE id = ?", allocation["job_id"])
			if err != nil {
				return err
			}
			if logsExpired(job, s.now()) {
				result.Status = "expired"
				return nil
			}
			identity = LogIdentity{text(allocation["job_id"]), text(allocation["attempt_id"]), text(allocation["component_id"]), integer(allocation["epoch"])}
			cursor := mapping(mapping(allocation["details_json"])["log_stream"])
			if source := text(cursor["source_id"]); source != "" && source != identity.Key() {
				return domain.Err(409, "log_cursor_conflict")
			}
			offset = integer(cursor["offset"])
			if offset < 0 || offset > MaxCanonicalLogBytes {
				return domain.Err(409, "log_cursor_conflict")
			}
			if flag(cursor["complete"]) {
				result.Status = "complete"
				result.Complete = true
				result.Truncated = flag(cursor["truncated"])
			}
			return nil
		})
		if e != nil {
			return result, e
		}
		if allocation == nil || result.Status == "expired" || result.Complete {
			return result, nil
		}
		receipt, e := s.ReadLogs(ctx, identity, offset, MaxLogChunkBytes)
		if e != nil {
			return result, e
		}
		if e = receipt.Validate(identity, offset); e != nil {
			return result, e
		}
		size := int64(len(receipt.Content))
		stored := int64(0)
		conflict := false
		e = s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
			project, e := tx.One(ctx, "SELECT * FROM jm_projects WHERE id = ?"+tx.ForUpdate(), job["project_id"])
			if e != nil {
				return e
			}
			currentJob, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id = ?"+tx.ForUpdate(), identity.JobID)
			if e != nil {
				return e
			}
			row, e := tx.One(ctx, "SELECT * FROM jm_allocations WHERE id = ?"+tx.ForUpdate(), allocationID)
			if e != nil {
				return e
			}
			if project == nil || row == nil || row["job_id"] != identity.JobID || row["attempt_id"] != identity.AttemptID || row["component_id"] != identity.ComponentID || integer(row["epoch"]) != identity.Epoch || logsExpired(currentJob, s.now()) {
				result.Status = "expired"
				return nil
			}
			d := copyMap(row["details_json"])
			cursor := mapping(d["log_stream"])
			if integer(cursor["offset"]) != offset || (text(cursor["source_id"]) != "" && text(cursor["source_id"]) != identity.Key()) {
				conflict = true
				return nil
			}
			if size > 0 {
				attempt, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE id = ?", identity.AttemptID)
				if e != nil {
					return e
				}
				if attempt == nil || attempt["job_id"] != identity.JobID || integer(attempt["epoch"]) != identity.Epoch {
					return domain.Err(422, "invalid_log_receipt")
				}
				stored, e = appendLogInTx(ctx, tx, project, currentJob, attempt, row, receipt.Content, s.now())
				if e != nil {
					return e
				}
			}
			dropped := size - stored
			exhausted = flag(cursor["budget_exhausted"]) || dropped > 0
			d["log_stream"] = map[string]any{"source_id": identity.Key(), "offset": receipt.NextOffset, "complete": receipt.Complete, "truncated": receipt.Truncated || exhausted, "dropped_bytes": integer(cursor["dropped_bytes"]) + dropped, "budget_exhausted": exhausted}
			return tx.Update(ctx, "jm_allocations", map[string]any{"id": allocationID}, map[string]any{"details_json": d})
		})
		if e != nil {
			var de *domain.Error
			if errors.As(e, &de) && de.Code == "retained_storage_quota_exceeded" {
				result.Status = "quota_exceeded"
				return result, nil
			}
			return result, e
		}
		if result.Status == "expired" {
			return result, nil
		}
		if conflict {
			result.Status = "concurrent_poll"
			return result, nil
		}
		if stored > 0 {
			result.Chunks++
		}
		result.Bytes += stored
		result.Complete = receipt.Complete
		result.Truncated = receipt.Truncated || exhausted
		if result.Complete || size == 0 || !terminal {
			if exhausted {
				result.Status = "limit_reached"
			} else if result.Complete {
				result.Status = "complete"
			} else if size == 0 {
				result.Status = "caught_up"
			} else {
				result.Status = "more_available"
			}
			return result, nil
		}
	}
	if exhausted {
		result.Status = "limit_reached"
	} else {
		result.Status = "more_available"
	}
	return result, nil
}

// AppendExternalLogs requires current mTLS/grant authorization by the caller.
// These persisted ownership checks supplement authentication; they do not replace it.
func (s *LogService) AppendExternalLogs(ctx context.Context, identity LogIdentity, receipt LogReceipt, resourceID, nodeID string) (map[string]any, error) {
	if nodeID == "" {
		return nil, domain.Err(422, "invalid_log_identity")
	}
	if e := receipt.Validate(identity, receipt.Offset); e != nil {
		return nil, e
	}
	var result map[string]any
	e := s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		observed, e := tx.One(ctx, "SELECT project_id FROM jm_jobs WHERE id = ?", identity.JobID)
		if e != nil {
			return e
		}
		if observed == nil {
			return domain.Err(404, "participant_assignment_not_found")
		}
		project, e := tx.One(ctx, "SELECT * FROM jm_projects WHERE id = ?"+tx.ForUpdate(), observed["project_id"])
		if e != nil {
			return e
		}
		job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id = ?"+tx.ForUpdate(), identity.JobID)
		if e != nil {
			return e
		}
		resource, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id = ?"+tx.ForUpdate(), resourceID)
		if e != nil {
			return e
		}
		attempt, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE id = ?", identity.AttemptID)
		if e != nil {
			return e
		}
		if resource == nil || attempt == nil || attempt["job_id"] != identity.JobID || integer(attempt["epoch"]) != identity.Epoch {
			return domain.Err(404, "participant_assignment_not_found")
		}
		d := copyMap(resource["details_json"])
		own := mapping(resource["ownership_json"])
		if text(resource["kind"]) != "external_execution" || resource["job_id"] != identity.JobID || resource["attempt_id"] != identity.AttemptID || resource["component_id"] != identity.ComponentID || text(resource["external_id"]) != identity.Key() || own["job_id"] != identity.JobID || own["attempt_id"] != identity.AttemptID || own["component_id"] != identity.ComponentID || text(d["node_id"]) != nodeID || integer(d["epoch"]) != identity.Epoch || text(resource["state"]) == "deleted" || resource["deleted_at"] != nil {
			return domain.Err(404, "participant_assignment_not_found")
		}
		if logsExpired(job, s.now()) {
			return domain.Err(410, "job_logs_expired")
		}
		cursor := mapping(d["log_stream"])
		offset := integer(cursor["offset"])
		if offset < 0 || offset > MaxCanonicalLogBytes || (text(cursor["source_id"]) != "" && text(cursor["source_id"]) != identity.Key()) {
			return domain.Err(409, "log_cursor_conflict")
		}
		if receipt.Offset < offset && receipt.NextOffset <= offset {
			result = map[string]any{"accepted": true, "next_offset": offset, "complete": flag(cursor["complete"]), "truncated": flag(cursor["truncated"])}
			return nil
		}
		if receipt.Offset != offset {
			return domain.Err(409, "log_cursor_conflict", map[string]any{"next_offset": offset})
		}
		if flag(cursor["complete"]) && receipt.Content != "" {
			return domain.Err(409, "log_stream_already_complete")
		}
		stored := int64(0)
		if receipt.Content != "" {
			stored, e = appendLogInTx(ctx, tx, project, job, attempt, resource, receipt.Content, s.now())
			if e != nil {
				return e
			}
		}
		dropped := int64(len(receipt.Content)) - stored
		exhausted := flag(cursor["budget_exhausted"]) || dropped > 0
		complete := receipt.Complete || flag(cursor["complete"])
		truncated := receipt.Truncated || flag(cursor["truncated"]) || exhausted
		d["log_stream"] = map[string]any{"source_id": identity.Key(), "offset": receipt.NextOffset, "complete": complete, "truncated": truncated, "dropped_bytes": integer(cursor["dropped_bytes"]) + dropped, "budget_exhausted": exhausted}
		if e = tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": resourceID}, map[string]any{"details_json": d}); e != nil {
			return e
		}
		result = map[string]any{"accepted": true, "next_offset": receipt.NextOffset, "complete": complete, "truncated": truncated}
		return nil
	})
	return result, e
}

// DecodeLogReceipt rejects unknown fields and ambiguous numeric values.
func DecodeLogReceipt(raw []byte) (LogReceipt, error) {
	var result LogReceipt
	value, e := domain.DecodeJSON(raw)
	if e != nil {
		return result, domain.Err(422, "invalid_log_receipt")
	}
	m, ok := value.(map[string]any)
	if !ok || len(m) != 7 {
		return result, domain.Err(422, "invalid_log_receipt")
	}
	for _, key := range []string{"identity", "source_id", "offset", "next_offset", "content", "complete", "truncated"} {
		if _, exists := m[key]; !exists {
			return result, domain.Err(422, "invalid_log_receipt")
		}
	}
	id := mapping(m["identity"])
	if len(id) != 4 {
		return result, domain.Err(422, "invalid_log_receipt")
	}
	result.Identity = LogIdentity{text(id["job_id"]), text(id["attempt_id"]), text(id["component_id"]), integer(id["epoch"])}
	result.SourceID = text(m["source_id"])
	if m["offset"] == nil || m["next_offset"] == nil {
		return result, domain.Err(422, "invalid_log_receipt")
	}
	result.Offset = integer(m["offset"])
	result.NextOffset = integer(m["next_offset"])
	var valid bool
	result.Content, valid = m["content"].(string)
	if !valid {
		return result, domain.Err(422, "invalid_log_receipt")
	}
	result.Complete, valid = m["complete"].(bool)
	if !valid {
		return result, domain.Err(422, "invalid_log_receipt")
	}
	result.Truncated, valid = m["truncated"].(bool)
	if !valid {
		return result, domain.Err(422, "invalid_log_receipt")
	}
	if e = result.Validate(result.Identity, result.Offset); e != nil {
		return result, e
	}
	return result, nil
}

var _ = json.Number("")
