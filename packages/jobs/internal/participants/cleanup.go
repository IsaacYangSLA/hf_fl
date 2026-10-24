package participants

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
	"golang.org/x/sys/unix"
)

// ExternalCleanup retains historical identities and accounting until each node
// acknowledges physical deletion with a certificate-bound, purge-only grant.
type ExternalCleanup struct{ Service *Service }

func NewExternalCleanup(s *Service) *ExternalCleanup { return &ExternalCleanup{Service: s} }
func cleanupObject(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}
func cleanupString(v any) string { s, _ := v.(string); return s }
func cleanupInt(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case json.Number:
		i, e := n.Int64()
		return i, e == nil
	}
	return 0, false
}
func cleanupTrue(v any) bool { b, ok := v.(bool); return ok && b }
func cleanupCopy(v map[string]any) map[string]any {
	r := map[string]any{}
	for k, x := range v {
		r[k] = x
	}
	return r
}
func cleanupPurgeScope(a Actor) bool { return len(a.Scopes) == 1 && a.Scopes[0] == "purge" }
func (c *ExternalCleanup) authorize(ctx context.Context, tx *store.Tx, job map[string]any) (domain.JobSpec, error) {
	if job == nil {
		return domain.JobSpec{}, domain.Err(404, "job_not_found")
	}
	expired := false
	if t, ok := store.Time(job["artifacts_expire_at"]); ok {
		expired = !t.After(c.Service.now())
	}
	if !domain.IsTerminal(cleanupString(job["state"])) || (cleanupString(job["cleanup_status"]) != "purge_pending" && !expired) {
		return domain.JobSpec{}, domain.Err(409, "participant_purge_not_authorized")
	}
	rows, e := tx.All(ctx, "SELECT * FROM jm_attempts WHERE job_id = ?", job["id"])
	if e != nil {
		return domain.JobSpec{}, e
	}
	for _, r := range rows {
		if !cleanupTrue(r["revocation_confirmed"]) || !cleanupTrue(r["termination_confirmed"]) {
			return domain.JobSpec{}, domain.Err(409, "participant_purge_termination_unconfirmed")
		}
	}
	rows, e = tx.All(ctx, "SELECT * FROM jm_provisioning_resources WHERE job_id = ? AND kind IN ('external_execution','external_enrollment')", job["id"])
	if e != nil {
		return domain.JobSpec{}, e
	}
	for _, r := range rows {
		if !cleanupTrue(cleanupObject(r["details_json"])["termination_confirmed"]) {
			return domain.JobSpec{}, domain.Err(409, "participant_purge_termination_unconfirmed")
		}
	}
	allocation, e := tx.One(ctx, "SELECT id FROM jm_allocations WHERE job_id = ? AND released_at IS NULL", job["id"])
	if e != nil {
		return domain.JobSpec{}, e
	}
	if allocation != nil {
		return domain.JobSpec{}, domain.Err(409, "participant_purge_termination_unconfirmed")
	}
	return domain.JobSpecFromMap(cleanupObject(job["spec_json"]))
}

type cleanupRecord struct {
	resource, job, attempt map[string]any
	spec                   domain.JobSpec
	participant            domain.ParticipantSpec
	node                   ApprovedNode
	digest                 string
}

func (c *ExternalCleanup) record(ctx context.Context, tx *store.Tx, a Actor, write bool) (cleanupRecord, error) {
	var r cleanupRecord
	if !cleanupPurgeScope(a) {
		return r, domain.Err(403, "node_scope_required")
	}
	suffix := ""
	if write {
		suffix = tx.ForUpdate()
	}
	job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id = ?"+suffix, a.JobID)
	if e != nil {
		return r, e
	}
	resource, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id = ?", a.GrantID)
	if e != nil {
		return r, e
	}
	attempt, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE id = ?", a.AttemptID)
	if e != nil {
		return r, e
	}
	missing := func() (cleanupRecord, error) { return r, domain.Err(404, "participant_purge_not_found") }
	if resource == nil || job == nil || attempt == nil || cleanupString(resource["kind"]) != "external_execution" || resource["job_id"] != job["id"] || attempt["job_id"] != job["id"] || resource["attempt_id"] != attempt["id"] || a.PoolID != "external" {
		return missing()
	}
	epoch, ok := cleanupInt(attempt["epoch"])
	if !ok || epoch != a.Epoch || cleanupString(resource["component_id"]) != a.ComponentID {
		return missing()
	}
	spec, e := c.authorize(ctx, tx, job)
	if e != nil {
		return r, e
	}
	digest, e := spec.Digest()
	if e != nil {
		return r, e
	}
	data, owner := cleanupObject(resource["details_json"]), cleanupObject(resource["ownership_json"])
	var participant domain.ParticipantSpec
	found := false
	for _, p := range spec.Participants {
		if p.ParticipantID == cleanupString(data["participant_id"]) && p.Mode == "external" {
			participant = p
			found = true
			break
		}
	}
	node, known := c.Service.Nodes[cleanupString(data["node_id"])]
	dep, dok := cleanupInt(data["epoch"])
	state := cleanupString(resource["state"])
	if !found || !known || resource["component_id"] != domain.ExternalComponentID(participant.ParticipantID) || !dok || dep != epoch || data["spec_digest"] != digest || !cleanupTrue(data["termination_confirmed"]) || a.NodeID != cleanupString(data["node_id"]) || a.CertificateThumbprint != cleanupString(data["node_certificate_thumbprint"]) || node.CertificateThumbprint != cleanupString(data["node_certificate_thumbprint"]) || owner["job_id"] != job["id"] || owner["attempt_id"] != attempt["id"] || owner["component_id"] != resource["component_id"] || (state != "ready" && state != "purge_pending" && state != "deleted") {
		return missing()
	}
	return cleanupRecord{resource, job, attempt, spec, participant, node, digest}, nil
}
func (c *ExternalCleanup) CheckNodeGrant(ctx context.Context, a Actor) bool {
	return c.Service.DB.WithTx(ctx, false, func(tx *store.Tx) error { _, e := c.record(ctx, tx, a, false); return e }) == nil
}
func (c *ExternalCleanup) PurgePlan(ctx context.Context, a Actor) (map[string]any, error) {
	var record cleanupRecord
	var manifest any
	e := c.Service.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		var e error
		record, e = c.record(ctx, tx, a, false)
		if e != nil {
			return e
		}
		manifest = cleanupObject(record.resource["details_json"])["source_manifest"]
		if manifest == nil {
			rows, e := tx.All(ctx, "SELECT * FROM jm_provisioning_resources WHERE job_id = ? AND component_id = ? AND kind = 'external_execution' ORDER BY created_at,id", a.JobID, a.ComponentID)
			if e != nil {
				return e
			}
			for _, row := range rows {
				data := cleanupObject(row["details_json"])
				if data["spec_digest"] == record.digest && data["source_manifest"] != nil {
					manifest = data["source_manifest"]
					break
				}
			}
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	if manifest == nil {
		// Snapshot hooks may refresh the source catalog through their own database
		// transaction. Release our SQL connection before invoking that boundary.
		snapshot, snapshotErr := c.Service.snapshot(ctx, record.job, record.spec)
		if snapshotErr == nil {
			manifest = snapshot.Manifest
		}
		// Source absence can still be proven from a node's pinned local runtime.
		// It never bypasses the current historical grant and termination fences.
		e = c.Service.DB.WithTx(ctx, false, func(tx *store.Tx) error {
			var e error
			record, e = c.record(ctx, tx, a, false)
			return e
		})
		if e != nil {
			return nil, e
		}
	}
	data := cleanupObject(record.resource["details_json"])
	return map[string]any{
		"identity": cleanupIdentity(executor.ExecutionIdentity{JobID: a.JobID, AttemptID: a.AttemptID, ComponentID: a.ComponentID, Epoch: a.Epoch}),
		"node_id":  record.node.NodeID, "pool_id": "external", "participant_id": record.participant.ParticipantID,
		"spec_digest": record.digest, "source_manifest": manifest, "termination_confirmed": true, "revocation_confirmed": true,
		"purged":                  record.resource["deleted_at"] != nil && cleanupTrue(data["disk_cleanup_confirmed"]),
		"preserve_dataset_inputs": true,
	}, nil
}

func (c *ExternalCleanup) ConfirmPurged(ctx context.Context, a Actor, confirmed bool) (map[string]any, error) {
	if !confirmed {
		return nil, domain.Err(422, "participant_purge_confirmation_required")
	}
	var result map[string]any
	e := c.Service.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		r, e := c.record(ctx, tx, a, true)
		if e != nil {
			return e
		}
		if r.resource["deleted_at"] == nil {
			now := c.Service.now()
			data := cleanupCopy(cleanupObject(r.resource["details_json"]))
			data["disk_cleanup_confirmed"] = true
			data["purged_at"] = now.Format(time.RFC3339Nano)
			if e := tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": r.resource["id"]}, map[string]any{"state": "deleted", "retained": false, "size_bytes": int64(0), "deleted_at": now, "updated_at": now, "details_json": data}); e != nil {
				return e
			}
			if e := c.Service.emit(ctx, tx, r.job, "participant.purged", "node:"+r.node.NodeID, map[string]any{"participant_id": r.participant.ParticipantID, "attempt_id": a.AttemptID, "component_id": a.ComponentID}); e != nil {
				return e
			}
		}
		result = map[string]any{"confirmed": true, "job_id": a.JobID, "attempt_id": a.AttemptID, "component_id": a.ComponentID, "epoch": a.Epoch}
		return nil
	})
	return result, e
}

const cleanupRowsSQL = "SELECT * FROM jm_provisioning_resources WHERE job_id = ? AND kind IN ('external_execution','external_enrollment','external_execution_certificate') ORDER BY created_at,id"

func cleanupOwned(rows []map[string]any, jobID string) error {
	for _, r := range rows {
		o := cleanupObject(r["ownership_json"])
		if o["job_id"] != jobID || o["component_id"] != r["component_id"] || (r["kind"] == "external_execution" && o["attempt_id"] != r["attempt_id"]) {
			return domain.Err(409, "participant_cleanup_ownership_mismatch")
		}
	}
	return nil
}
func (c *ExternalCleanup) PurgeJob(ctx context.Context, jobID string) (bool, error) {
	type dispatch struct {
		node string
		doc  map[string]any
	}
	pending := []dispatch{}
	blocked := false
	e := c.Service.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id = ?"+tx.ForUpdate(), jobID)
		if e != nil {
			return e
		}
		if _, e = c.authorize(ctx, tx, job); e != nil {
			return e
		}
		rows, e := tx.All(ctx, cleanupRowsSQL, jobID)
		if e != nil {
			return e
		}
		if e = cleanupOwned(rows, jobID); e != nil {
			return e
		}
		owned := map[string]bool{}
		for _, r := range rows {
			if r["kind"] == "external_execution" {
				owned[fmt.Sprint(r["attempt_id"], "/", r["component_id"])] = true
			}
		}
		for _, r := range rows {
			if r["kind"] == "external_enrollment" && r["attempt_id"] != nil && !owned[fmt.Sprint(r["attempt_id"], "/", r["component_id"])] {
				blocked = true
				return nil
			}
		}
		sort.SliceStable(rows, func(i, j int) bool {
			return cleanupObject(rows[i]["details_json"])["source_manifest"] != nil && cleanupObject(rows[j]["details_json"])["source_manifest"] == nil
		})
		for _, r := range rows {
			if r["kind"] != "external_execution" {
				continue
			}
			d := cleanupObject(r["details_json"])
			if r["deleted_at"] != nil && cleanupTrue(d["disk_cleanup_confirmed"]) {
				continue
			}
			node, ok := c.Service.Nodes[cleanupString(d["node_id"])]
			if !ok || node.CertificateThumbprint != cleanupString(d["node_certificate_thumbprint"]) {
				blocked = true
				return nil
			}
			epoch, ok := cleanupInt(d["epoch"])
			if !ok || epoch < 1 || cleanupString(r["attempt_id"]) == "" {
				blocked = true
				return nil
			}
			token, e := c.Service.issueNode(ctx, NodeGrant{NodeID: node.NodeID, PoolID: "external", JobID: jobID, AttemptID: cleanupString(r["attempt_id"]), ComponentID: cleanupString(r["component_id"]), GrantID: cleanupString(r["id"]), Epoch: epoch, CertificateThumbprint: node.CertificateThumbprint, Scopes: []string{"purge"}})
			if e != nil {
				return e
			}
			if e = tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": r["id"]}, map[string]any{"state": "purge_pending"}); e != nil {
				return e
			}
			pending = append(pending, dispatch{node.NodeID, map[string]any{"enrollment": map[string]any{"id": r["id"], "job_id": jobID, "attempt_id": r["attempt_id"], "component_id": r["component_id"], "epoch": epoch, "participant_id": d["participant_id"], "node_id": node.NodeID, "status": "purge_pending", "external": true, "manager_allocation": false}, "node_token": token, "node_certificate_thumbprint": node.CertificateThumbprint, "operation": "purge"}})
		}
		return nil
	})
	if e != nil || blocked {
		return false, e
	}
	if len(pending) > 0 && c.Service.Dispatch == nil {
		return false, nil
	}
	for _, p := range pending {
		if _, e = c.Service.Dispatch(ctx, p.node, p.doc); e != nil {
			return false, nil
		}
	}
	complete := false
	e = c.Service.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id = ?"+tx.ForUpdate(), jobID)
		if e != nil {
			return e
		}
		if _, e = c.authorize(ctx, tx, job); e != nil {
			return e
		}
		rows, e := tx.All(ctx, cleanupRowsSQL, jobID)
		if e != nil {
			return e
		}
		if e = cleanupOwned(rows, jobID); e != nil {
			return e
		}
		for _, r := range rows {
			if r["kind"] == "external_execution" && (r["deleted_at"] == nil || !cleanupTrue(cleanupObject(r["details_json"])["disk_cleanup_confirmed"])) {
				return nil
			}
		}
		now := c.Service.now()
		for _, r := range rows {
			if r["deleted_at"] != nil {
				continue
			}
			d := cleanupCopy(cleanupObject(r["details_json"]))
			d["disk_cleanup_confirmed"] = true
			if e = tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": r["id"]}, map[string]any{"state": "deleted", "retained": false, "size_bytes": int64(0), "deleted_at": now, "updated_at": now, "details_json": d}); e != nil {
				return e
			}
		}
		complete = true
		return nil
	})
	return complete, e
}
func cleanupIdentity(i executor.ExecutionIdentity) map[string]any {
	return map[string]any{"job_id": i.JobID, "attempt_id": i.AttemptID, "component_id": i.ComponentID, "epoch": i.Epoch}
}

// CleanupAgent supplies independently fenced node/materializer capabilities.
// WithPurgeGuard must exclude starts and reservations for this whole component
// across processes until fn returns. Missing or unknown capabilities must error.
type CleanupAgent interface {
	WithPurgeGuard(context.Context, executor.ExecutionIdentity, func() error) error
	Request(context.Context, executor.ExecutionIdentity, string, string, map[string]any) (map[string]any, error)
	NodeID() string
	Inventory(context.Context) ([]CleanupReservation, error)
	ConfirmAbsent(context.Context, executor.ExecutionIdentity) (bool, error)
	Assignment(context.Context, executor.ExecutionIdentity) (*CleanupAssignment, error)
	AllAssignments(context.Context) ([]CleanupAssignment, error)
	OwnedRoot() string
	PurgePrivate(context.Context, executor.ExecutionIdentity, *CleanupAssignment) (bool, error)
	PurgeRuntime(context.Context, executor.ExecutionIdentity, bool) (bool, error)
	RemoveAssignment(context.Context, executor.ExecutionIdentity) error
}
type CleanupReservation struct {
	Identity executor.ExecutionIdentity
	State    string
	Stopped  bool
}
type CleanupAssignment struct {
	Identity                                                             executor.ExecutionIdentity
	NodeID, PoolID, SpecDigest, ParticipantID, ComponentRoot, SourceRoot string
	DiskBytes                                                            int64
}
type cleanupReceipt struct {
	Identity       executor.ExecutionIdentity `json:"identity"`
	SpecDigest     string                     `json:"spec_digest"`
	ParticipantID  string                     `json:"participant_id"`
	NodeID         string                     `json:"node_id"`
	SourceManifest map[string]string          `json:"source_manifest"`
	Purged         bool                       `json:"purged"`
}

func cleanupMismatch() error { return domain.Err(409, "participant_cleanup_ownership_mismatch") }
func cleanupMissing() error  { return domain.Err(409, "participant_cleanup_ownership_missing") }
func cleanupEqual(a, b any) bool {
	x, e := domain.CanonicalJSON(a)
	if e != nil {
		return false
	}
	y, e := domain.CanonicalJSON(b)
	return e == nil && string(x) == string(y)
}
func cleanupManifest(v any) (map[string]string, error) {
	var m map[string]string
	switch x := v.(type) {
	case map[string]string:
		m = x
	case map[string]any:
		m = map[string]string{}
		for k, v := range x {
			s, ok := v.(string)
			if !ok {
				return nil, cleanupMismatch()
			}
			m[k] = s
		}
	default:
		return nil, domain.Err(409, "participant_source_ownership_missing")
	}
	if len(m) > 100000 {
		return nil, cleanupMismatch()
	}
	for p, h := range m {
		if !cleanupRelative(p) || len(h) != 64 {
			return nil, cleanupMismatch()
		}
		b, e := hex.DecodeString(h)
		if e != nil || hex.EncodeToString(b) != h {
			return nil, cleanupMismatch()
		}
	}
	return m, nil
}
func cleanupRelative(p string) bool {
	if p == "" || len(p) > 4096 || filepath.IsAbs(p) || strings.Contains(p, "\\") {
		return false
	}
	for _, x := range strings.Split(p, "/") {
		if x == "" || x == "." || x == ".." {
			return false
		}
	}
	return true
}

// cleanupOpenAbsolute resolves every ancestor without following symbolic links.
func cleanupOpenAbsolute(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, cleanupMismatch()
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, e
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
	}
	return fd, nil
}
func cleanupCheckDir(fd int, device uint64) error {
	var st unix.Stat_t
	if e := unix.Fstat(fd, &st); e != nil {
		return e
	}
	if uint64(st.Dev) != device || st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 {
		return cleanupMismatch()
	}
	return nil
}
func cleanupReadAt(fd int, name string, max int64) ([]byte, error) {
	f, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	file := os.NewFile(uintptr(f), name)
	defer file.Close()
	var st unix.Stat_t
	if e = unix.Fstat(f, &st); e != nil {
		return nil, e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || st.Size < 0 || st.Size > max {
		return nil, cleanupMismatch()
	}
	b, e := io.ReadAll(io.LimitReader(file, max+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > max {
		return nil, cleanupMismatch()
	}
	return b, nil
}
func cleanupReceiptRead(fd int, name string) (*cleanupReceipt, error) {
	b, e := cleanupReadAt(fd, name, 16<<20)
	if errors.Is(e, unix.ENOENT) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	raw, e := domain.DecodeJSON(b)
	if e != nil {
		return nil, cleanupMismatch()
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, cleanupMismatch()
	}
	if _, ok = m["purged"].(bool); !ok {
		return nil, cleanupMismatch()
	}
	manifest, e := cleanupManifest(m["source_manifest"])
	if e != nil {
		return nil, e
	}
	var r cleanupReceipt
	if e = json.Unmarshal(b, &r); e != nil {
		return nil, cleanupMismatch()
	}
	r.SourceManifest = manifest
	return &r, nil
}
func cleanupReceiptWrite(fd int, name string, r cleanupReceipt) error {
	b, e := domain.CanonicalJSON(r)
	if e != nil {
		return e
	}
	tmp := ".pending-" + domain.NewID()
	f, e := unix.Openat(fd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	file := os.NewFile(uintptr(f), tmp)
	defer unix.Unlinkat(fd, tmp, 0)
	_, e = file.Write(b)
	if e == nil {
		e = file.Sync()
	}
	closeErr := file.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if e = unix.Renameat(fd, tmp, fd, name); e != nil {
		return e
	}
	return unix.Fsync(fd)
}

type cleanupTree struct {
	fd    int
	st    unix.Stat_t
	files []cleanupTreeFile
	dirs  []cleanupTreeDir
}
type cleanupTreeFile struct {
	name string
	st   unix.Stat_t
}
type cleanupTreeDir struct {
	name string
	tree *cleanupTree
}

func (t *cleanupTree) close() {
	for _, d := range t.dirs {
		d.tree.close()
	}
	unix.Close(t.fd)
}
func cleanupCollect(fd int, device uint64, prefix string, manifest map[string]string, budget *int64, entries *int) (*cleanupTree, error) {
	if strings.Count(prefix, "/") >= 64 {
		return nil, cleanupMismatch()
	}
	t := &cleanupTree{fd: fd}
	complete := false
	defer func() {
		if !complete {
			for _, d := range t.dirs {
				d.tree.close()
			}
		}
	}()
	if e := unix.Fstat(fd, &t.st); e != nil {
		return nil, e
	}
	if e := cleanupCheckDir(fd, device); e != nil {
		return nil, e
	}
	// Dup gives the directory reader its own cursor and leaves fd pinned.
	dup, e := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	reader := os.NewFile(uintptr(dup), "cleanup")
	names, e := reader.Readdirnames(-1)
	reader.Close()
	if e != nil {
		return nil, e
	}
	for _, name := range names {
		*entries++
		if *entries > 200000 {
			return nil, cleanupMismatch()
		}
		var st unix.Stat_t
		if e = unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
			return nil, e
		}
		if uint64(st.Dev) != device || st.Uid != uint32(os.Geteuid()) {
			return nil, cleanupMismatch()
		}
		rel := name
		if prefix != "" {
			rel = prefix + "/" + name
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			child, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if e != nil {
				return nil, e
			}
			tree, e := cleanupCollect(child, device, rel, manifest, budget, entries)
			if e != nil {
				unix.Close(child)
				return nil, e
			}
			t.dirs = append(t.dirs, cleanupTreeDir{name, tree})
		case unix.S_IFREG:
			if st.Nlink != 1 || st.Size < 0 || st.Size > *budget {
				return nil, cleanupMismatch()
			}
			*budget -= st.Size
			f, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
			if e != nil {
				return nil, e
			}
			file := os.NewFile(uintptr(f), name)
			var current unix.Stat_t
			e = unix.Fstat(f, &current)
			if e == nil && (current.Dev != st.Dev || current.Ino != st.Ino || current.Nlink != 1) {
				e = cleanupMismatch()
			}
			hash := sha256.New()
			var n int64
			if e == nil {
				n, e = io.Copy(hash, io.LimitReader(file, st.Size+1))
				if n != st.Size {
					e = cleanupMismatch()
				}
			}
			file.Close()
			if e != nil {
				return nil, e
			}
			if manifest != nil && manifest[rel] != hex.EncodeToString(hash.Sum(nil)) {
				return nil, domain.Err(409, "participant_source_ownership_mismatch")
			}
			t.files = append(t.files, cleanupTreeFile{name, st})
		default:
			return nil, cleanupMismatch()
		}
	}
	complete = true
	return t, nil
}
func cleanupSame(fd int, name string, st unix.Stat_t) error {
	var now unix.Stat_t
	if e := unix.Fstatat(fd, name, &now, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return e
	}
	if now.Dev != st.Dev || now.Ino != st.Ino || now.Mode&unix.S_IFMT != st.Mode&unix.S_IFMT || now.Size != st.Size || now.Nlink != st.Nlink || now.Uid != st.Uid {
		return cleanupMismatch()
	}
	return nil
}
func (t *cleanupTree) remove() error {
	if e := unix.Fchmod(t.fd, 0700); e != nil {
		return e
	}
	for _, f := range t.files {
		if e := cleanupSame(t.fd, f.name, f.st); e != nil {
			return e
		}
		if e := unix.Unlinkat(t.fd, f.name, 0); e != nil {
			return e
		}
	}
	for _, d := range t.dirs {
		if e := d.tree.remove(); e != nil {
			return e
		}
		// Directory sizes and link counts change during their contents' deletion.
		var current unix.Stat_t
		if e := unix.Fstatat(t.fd, d.name, &current, unix.AT_SYMLINK_NOFOLLOW); e != nil {
			return e
		}
		if current.Dev != d.tree.st.Dev || current.Ino != d.tree.st.Ino || current.Mode&unix.S_IFMT != unix.S_IFDIR {
			return cleanupMismatch()
		}
		if e := unix.Unlinkat(t.fd, d.name, unix.AT_REMOVEDIR); e != nil {
			return e
		}
	}
	return unix.Fsync(t.fd)
}

// cleanupOwnedTree deletes through descriptors only after the entire bounded
// tree passes ownership, mount, link and (for source) pinned-hash validation.
func cleanupOwnedTree(parent int, name string, maxBytes int64, manifest map[string]string) error {
	fd, e := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil {
		return e
	}
	var st unix.Stat_t
	if e = unix.Fstat(parent, &st); e != nil {
		unix.Close(fd)
		return e
	}
	count := 0
	tree, e := cleanupCollect(fd, uint64(st.Dev), "", manifest, &maxBytes, &count)
	if e != nil {
		if tree != nil {
			tree.close()
		} else {
			unix.Close(fd)
		}
		return e
	}
	defer tree.close()
	if e = tree.remove(); e != nil {
		return e
	}
	var current unix.Stat_t
	if e = unix.Fstatat(parent, name, &current, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return e
	}
	if current.Dev != tree.st.Dev || current.Ino != tree.st.Ino || current.Mode&unix.S_IFMT != unix.S_IFDIR {
		return cleanupMismatch()
	}
	if e = unix.Unlinkat(parent, name, unix.AT_REMOVEDIR); e != nil {
		return e
	}
	return unix.Fsync(parent)
}
func cleanupOpenChild(fd int, name string) (int, error) {
	child, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, e
	}
	var parent unix.Stat_t
	if e = unix.Fstat(fd, &parent); e == nil {
		e = cleanupCheckDir(child, uint64(parent.Dev))
	}
	if e != nil {
		unix.Close(child)
		return -1, e
	}
	return child, nil
}
func cleanupPathAbsent(fd int, parts ...string) error {
	current, e := unix.Dup(fd)
	if e != nil {
		return e
	}
	defer func() { unix.Close(current) }()
	for i, p := range parts {
		var st unix.Stat_t
		e = unix.Fstatat(current, p, &st, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(e, unix.ENOENT) {
			return nil
		}
		if e != nil {
			return e
		}
		if i == len(parts)-1 {
			return cleanupMissing()
		}
		next, e := cleanupOpenChild(current, p)
		if e != nil {
			return e
		}
		unix.Close(current)
		current = next
	}
	return cleanupMissing()
}

// PurgeAssignment obtains online authorization while holding the full component
// guard, records recoverable receipts, and releases disk only after private and
// materialized bytes have been deleted. Dataset approvals are never targets.
func PurgeAssignment(ctx context.Context, agent CleanupAgent, a Actor, identity executor.ExecutionIdentity, token string) (map[string]any, error) {
	if agent == nil {
		return nil, domain.Err(503, "participant_cleanup_unavailable")
	}
	if identity.Validate() != nil || !cleanupPurgeScope(a) || a.JobID != identity.JobID || a.AttemptID != identity.AttemptID || a.ComponentID != identity.ComponentID || a.Epoch != identity.Epoch || a.NodeID != agent.NodeID() || a.PoolID != "external" {
		return nil, domain.Err(403, "node_scope_required")
	}
	e := agent.WithPurgeGuard(ctx, identity, func() error { return cleanupPurgeAssignment(ctx, agent, a, identity, token) })
	if e != nil {
		return nil, e
	}
	return map[string]any{"accepted": true, "state": "purged"}, nil
}
func cleanupPurgeAssignment(ctx context.Context, agent CleanupAgent, a Actor, i executor.ExecutionIdentity, token string) error {
	plan, e := agent.Request(ctx, i, token, "purge-plan", nil)
	if e != nil {
		return e
	}
	if !cleanupEqual(plan["identity"], cleanupIdentity(i)) || plan["node_id"] != agent.NodeID() || plan["pool_id"] != "external" || !cleanupTrue(plan["termination_confirmed"]) || !cleanupTrue(plan["revocation_confirmed"]) || !cleanupTrue(plan["preserve_dataset_inputs"]) {
		return domain.Err(403, "external_node_assignment_mismatch")
	}
	digest, participant := cleanupString(plan["spec_digest"]), cleanupString(plan["participant_id"])
	if digest == "" || participant == "" {
		return cleanupMismatch()
	}
	root, e := cleanupOpenAbsolute(agent.OwnedRoot())
	if e != nil {
		return e
	}
	defer unix.Close(root)
	var rootStat unix.Stat_t
	if e = unix.Fstat(root, &rootStat); e != nil {
		return e
	}
	if e = cleanupCheckDir(root, uint64(rootStat.Dev)); e != nil {
		return e
	}
	if e = unix.Mkdirat(root, "purges", 0700); e != nil && !errors.Is(e, unix.EEXIST) {
		return e
	}
	purges, e := cleanupOpenChild(root, "purges")
	if e != nil {
		return e
	}
	defer unix.Close(purges)
	name := i.Key() + ".json"
	prior, e := cleanupReceiptRead(purges, name)
	if e != nil {
		return e
	}
	receipt := cleanupReceipt{Identity: i, SpecDigest: digest, ParticipantID: participant, NodeID: agent.NodeID()}
	if prior != nil && (prior.Identity != i || prior.SpecDigest != digest || prior.ParticipantID != participant || prior.NodeID != agent.NodeID()) {
		return cleanupMismatch()
	}
	assignment, e := agent.Assignment(ctx, i)
	if e != nil {
		return e
	}
	if assignment != nil && (assignment.Identity != i || assignment.NodeID != agent.NodeID() || assignment.PoolID != "external" || assignment.SpecDigest != digest || assignment.ParticipantID != participant) {
		return cleanupMismatch()
	}
	assignments, e := agent.AllAssignments(ctx)
	if e != nil {
		return e
	}
	expectedComponent := filepath.Join(agent.OwnedRoot(), "jobs", i.JobID, "components", i.ComponentID)
	for _, other := range assignments {
		if other.Identity.JobID != i.JobID || other.Identity.ComponentID != i.ComponentID {
			continue
		}
		if other.Identity.Validate() != nil || other.SpecDigest != digest || other.ParticipantID != participant || other.NodeID != agent.NodeID() || other.PoolID != "external" || (other.ComponentRoot != "" && other.ComponentRoot != expectedComponent) || (other.SourceRoot != "" && other.SourceRoot != filepath.Join(expectedComponent, "source")) {
			return cleanupMismatch()
		}
	}
	if prior != nil && prior.Purged {
		if assignment != nil {
			if e = agent.RemoveAssignment(ctx, i); e != nil {
				return e
			}
		}
		_, e = agent.Request(ctx, i, token, "purged", map[string]any{"confirmed": true})
		return e
	}
	rows, e := agent.Inventory(ctx)
	if e != nil {
		return e
	}
	found := false
	for _, r := range rows {
		if r.Identity.JobID == i.JobID && r.Identity.ComponentID == i.ComponentID {
			if r.State != "RELEASED" || !r.Stopped {
				return domain.Err(409, "participant_purge_termination_unconfirmed")
			}
			if r.Identity == i {
				found = true
			}
		}
	}
	if !found {
		absent, e := agent.ConfirmAbsent(ctx, i)
		if e != nil {
			return e
		}
		if !absent {
			return cleanupMissing()
		}
	}
	if assignment == nil {
		// No assignment must also mean no ledger row or orphaned owned bytes.
		if found {
			return cleanupMissing()
		}
		jobs, e := cleanupOpenChild(root, "jobs")
		if e != nil && !errors.Is(e, unix.ENOENT) {
			return e
		}
		if e == nil {
			defer unix.Close(jobs)
			job, e := cleanupOpenChild(jobs, i.JobID)
			if e != nil && !errors.Is(e, unix.ENOENT) {
				return e
			}
			if e == nil {
				defer unix.Close(job)
				components, e := cleanupOpenChild(job, "components")
				if e != nil && !errors.Is(e, unix.ENOENT) {
					return e
				}
				if e == nil {
					defer unix.Close(components)
					component, e := cleanupOpenChild(components, i.ComponentID)
					if e != nil && !errors.Is(e, unix.ENOENT) {
						return e
					}
					if e == nil {
						defer unix.Close(component)
						for _, p := range [][]string{{"source"}, {"state"}, {"attempts", i.AttemptID}} {
							if e = cleanupPathAbsent(component, p...); e != nil {
								return e
							}
						}
					}
				}
			}
		}
		ok, e := agent.PurgePrivate(ctx, i, nil)
		if e != nil {
			return e
		}
		if !ok {
			return domain.Err(503, "participant_secret_cleanup_unconfirmed")
		}
		receipt.SourceManifest = map[string]string{}
		receipt.Purged = true
		if e = cleanupReceiptWrite(purges, name, receipt); e != nil {
			return e
		}
	} else {
		expected := filepath.Join(agent.OwnedRoot(), "jobs", i.JobID, "components", i.ComponentID)
		if assignment.ComponentRoot != "" && assignment.ComponentRoot != expected {
			return cleanupMismatch()
		}
		if assignment.SourceRoot != "" && assignment.SourceRoot != filepath.Join(expected, "source") {
			return cleanupMismatch()
		}
		if assignment.DiskBytes < 1 || assignment.DiskBytes > 1<<50 {
			return cleanupMismatch()
		}
		jobs, e := cleanupOpenChild(root, "jobs")
		if e != nil {
			return e
		}
		defer unix.Close(jobs)
		job, e := cleanupOpenChild(jobs, i.JobID)
		if e != nil {
			return e
		}
		defer unix.Close(job)
		b, e := cleanupReadAt(job, ".owner.json", 4<<20)
		if e != nil {
			return e
		}
		owner, e := domain.DecodeJSON(b)
		if e != nil {
			return cleanupMismatch()
		}
		o := cleanupObject(owner)
		if o["job_id"] != i.JobID || o["spec_digest"] != digest {
			return cleanupMismatch()
		}
		components, e := cleanupOpenChild(job, "components")
		if e != nil {
			return e
		}
		defer unix.Close(components)
		component, e := cleanupOpenChild(components, i.ComponentID)
		// A pending tombstone permits resume after its component tree was removed.
		if errors.Is(e, unix.ENOENT) && prior != nil {
			receipt.SourceManifest = prior.SourceManifest
		} else {
			if e != nil {
				return e
			}
			if prior != nil {
				receipt.SourceManifest = prior.SourceManifest
			} else if plan["source_manifest"] != nil {
				receipt.SourceManifest, e = cleanupManifest(plan["source_manifest"])
				if e != nil {
					unix.Close(component)
					return e
				}
			} else {
				receipt.SourceManifest, e = cleanupRuntimeManifest(component, i, digest)
				if e != nil {
					unix.Close(component)
					return e
				}
			}
			if e = cleanupReceiptWrite(purges, name, receipt); e == nil {
				e = cleanupOwnedTree(component, "source", 1<<30, receipt.SourceManifest)
			}
			unix.Close(component)
			if e != nil {
				return e
			}
			if e = cleanupOwnedTree(components, i.ComponentID, 2*assignment.DiskBytes+(1<<30)+(16<<20), nil); e != nil {
				return e
			}
		}
		ok, e := agent.PurgePrivate(ctx, i, assignment)
		if e != nil {
			return e
		}
		if !ok {
			return domain.Err(503, "participant_secret_cleanup_unconfirmed")
		}
		ok, e = agent.PurgeRuntime(ctx, i, true)
		if e != nil {
			return e
		}
		if !ok {
			return domain.Err(503, "participant_disk_cleanup_unconfirmed")
		}
		receipt.Purged = true
		if e = cleanupReceiptWrite(purges, name, receipt); e != nil {
			return e
		}
		if e = agent.RemoveAssignment(ctx, i); e != nil {
			return e
		}
	}
	_, e = agent.Request(ctx, i, token, "purged", map[string]any{"confirmed": true})
	return e
}

// cleanupRuntimeManifest accepts only this execution's immutable runtime
// config as a fallback. Malformed, linked, or foreign configs never prove ownership.
func cleanupRuntimeManifest(component int, i executor.ExecutionIdentity, digest string) (map[string]string, error) {
	current, e := unix.Dup(component)
	if e != nil {
		return nil, e
	}
	defer func() { unix.Close(current) }()
	missing := func() (map[string]string, error) {
		if e := cleanupPathAbsent(component, "source"); e != nil {
			return nil, domain.Err(409, "participant_source_ownership_missing")
		}
		return map[string]string{}, nil
	}
	for _, part := range []string{"attempts", i.AttemptID, strconv.FormatInt(i.Epoch, 10)} {
		next, e := cleanupOpenChild(current, part)
		if errors.Is(e, unix.ENOENT) {
			return missing()
		}
		if e != nil {
			return nil, e
		}
		unix.Close(current)
		current = next
	}
	b, e := cleanupReadAt(current, "runtime.json", 4<<20)
	if errors.Is(e, unix.ENOENT) {
		return missing()
	}
	if e != nil {
		return nil, e
	}
	raw, e := domain.DecodeJSON(b)
	if e != nil {
		return nil, cleanupMismatch()
	}
	runtime := cleanupObject(raw)
	spec, e := domain.JobSpecFromMap(cleanupObject(runtime["spec"]))
	if e != nil {
		return nil, cleanupMismatch()
	}
	rd, e := spec.Digest()
	epoch, valid := cleanupInt(runtime["epoch"])
	if e != nil || rd != digest || runtime["job_id"] != i.JobID || runtime["attempt_id"] != i.AttemptID || runtime["component_id"] != i.ComponentID || !valid || epoch != i.Epoch {
		return nil, cleanupMismatch()
	}
	return cleanupManifest(runtime["source_manifest"])
}
