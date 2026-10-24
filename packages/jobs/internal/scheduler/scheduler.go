// Package scheduler implements transaction-owned gang admission and resource accounting.
package scheduler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

var Dimensions = []string{"cpu_millicores", "memory_bytes", "disk_bytes", "gpu_count"}
var LiveAllocationStates = []string{"RESERVED", "ACKNOWLEDGED", "STARTING", "RUNNING", "QUARANTINED", "RELEASING"}

const MaxBackfills int64 = 3

type Amounts map[string]int64

type Admission struct {
	JobID         string   `json:"job_id"`
	AttemptID     string   `json:"attempt_id"`
	Epoch         int64    `json:"epoch"`
	AllocationIDs []string `json:"allocation_ids"`
}

// StoragePlan is produced only by trusted provisioning, never by a job request.
type StoragePlan struct {
	Kind                string         `json:"kind"`
	ExternalID          string         `json:"external_id"`
	ComponentID         string         `json:"component_id"`
	PoolID              string         `json:"pool_id"`
	MaxBytes            int64          `json:"max_bytes"`
	CoveredByAllocation bool           `json:"covered_by_allocation"`
	Details             map[string]any `json:"details"`
}

type StoragePlanner func(context.Context, map[string]any) ([]StoragePlan, error)

// StoragePlannerTx reads durable resources in the admission transaction.
type StoragePlannerTx func(context.Context, *store.Tx, map[string]any) ([]StoragePlan, error)
type Scheduler struct {
	DB                 *store.DB
	Clock              func() time.Time
	AdmissionStorage   StoragePlanner
	AdmissionStorageTx StoragePlannerTx
}
type Option func(*Scheduler)

func WithClock(clock func() time.Time) Option { return func(s *Scheduler) { s.Clock = clock } }
func WithStoragePlanner(planner StoragePlanner) Option {
	return func(s *Scheduler) { s.AdmissionStorage = planner }
}

// WithTransactionalStoragePlanner avoids nested transactions during admission.
func WithTransactionalStoragePlanner(planner StoragePlannerTx) Option {
	return func(s *Scheduler) { s.AdmissionStorageTx = planner }
}
func New(db *store.DB, options ...Option) *Scheduler {
	s := &Scheduler{DB: db, Clock: func() time.Time { return time.Now().UTC() }}
	for _, opt := range options {
		opt(s)
	}
	return s
}
func (s *Scheduler) Tick(ctx context.Context) ([]Admission, error) { return s.Schedule(ctx, 100) }

// ExactInteger accepts SQL NUMERIC sums without converting budget units through float64.
func ExactInteger(v any) (int64, error) {
	switch x := v.(type) {
	case int:
		if x >= 0 {
			return int64(x), nil
		}
	case int64:
		if x >= 0 {
			return x, nil
		}
	case int32:
		if x >= 0 {
			return int64(x), nil
		}
	case uint64:
		if x <= math.MaxInt64 {
			return int64(x), nil
		}
	case json.Number:
		return exactDecimal(string(x))
	case string:
		return exactDecimal(x)
	case []byte:
		return exactDecimal(string(x))
	case *big.Int:
		if x != nil && x.Sign() >= 0 && x.IsInt64() {
			return x.Int64(), nil
		}
	}
	return 0, errors.New("resource accounting returned a non-integral quantity")
}
func exactDecimal(x string) (int64, error) {
	r, ok := new(big.Rat).SetString(x)
	if !ok || r.Sign() < 0 || !r.IsInt() || !r.Num().IsInt64() {
		return 0, errors.New("resource accounting returned a non-integral quantity")
	}
	return r.Num().Int64(), nil
}
func number(row map[string]any, key string) (int64, error) {
	if row == nil {
		return 0, fmt.Errorf("missing accounting row for %s", key)
	}
	if row[key] == nil {
		return 0, nil
	}
	return ExactInteger(row[key])
}
func add(a, b int64) (int64, error) {
	if a < 0 || b < 0 || a > math.MaxInt64-b {
		return 0, errors.New("resource accounting overflow")
	}
	return a + b, nil
}
func addTo(a Amounts, key string, n int64) error {
	sum, e := add(a[key], n)
	if e == nil {
		a[key] = sum
	}
	return e
}
func zero() Amounts {
	a := Amounts{}
	for _, k := range Dimensions {
		a[k] = 0
	}
	return a
}
func clone(m map[string]any) map[string]any {
	r := map[string]any{}
	for k, v := range m {
		r[k] = v
	}
	return r
}
func obj(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}
func str(v any) string { s, _ := v.(string); return s }
func yes(v any) bool   { b, _ := v.(bool); return b }
func list(v any) []string {
	switch x := v.(type) {
	case []string:
		return append([]string(nil), x...)
	case []any:
		r := []string{}
		for _, v := range x {
			if s, ok := v.(string); ok {
				r = append(r, s)
			}
		}
		return r
	}
	return nil
}
func contains(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}
func sortedKeys[V any](m map[string]V) []string {
	r := make([]string, 0, len(m))
	for k := range m {
		r = append(r, k)
	}
	sort.Strings(r)
	return r
}
func values(r domain.ResourceRequest) Amounts {
	return Amounts{"cpu_millicores": r.CPUMillicores, "memory_bytes": r.MemoryBytes, "disk_bytes": r.DiskBytes, "gpu_count": r.GPUCount}
}

// RequestedByPool sums a complete job's components. Validated domain bounds keep these sums in int64.
func RequestedByPool(spec domain.JobSpec) map[string]Amounts {
	result := map[string]Amounts{}
	for _, c := range spec.Components {
		if result[c.Resources.PoolID] == nil {
			result[c.Resources.PoolID] = zero()
		}
		for k, v := range values(c.Resources) {
			result[c.Resources.PoolID][k] += v
		}
	}
	return result
}
func PoolCapacity(pool map[string]any) (Amounts, error) {
	result := zero()
	for _, k := range Dimensions {
		if k == "gpu_count" {
			result[k] = int64(len(list(pool["gpu_uuids"])))
			continue
		}
		n, e := number(pool, k)
		if e != nil {
			return nil, e
		}
		result[k] = n
	}
	return result, nil
}

// Quota intersects legacy scalar columns with the explicit quota object.
func Quota(project map[string]any) (Amounts, error) {
	result := Amounts{}
	for k, v := range obj(project["quotas_json"]) {
		n, e := ExactInteger(v)
		if e != nil {
			return nil, e
		}
		result[k] = n
	}
	legacy := map[string]string{"cpu_millicores": "quota_cpu_millicores", "memory_bytes": "quota_memory_bytes", "disk_bytes": "quota_disk_bytes", "gpu_count": "quota_gpus", "max_running_jobs": "max_active_jobs"}
	for k, col := range legacy {
		if project[col] != nil {
			n, e := ExactInteger(project[col])
			if e != nil {
				return nil, e
			}
			if old, ok := result[k]; !ok || n < old {
				result[k] = n
			}
		}
	}
	return result, nil
}

func ValidateAdmission(ctx context.Context, tx *store.Tx, spec domain.JobSpec) error {
	requested := RequestedByPool(spec)
	project, err := tx.One(ctx, "SELECT * FROM jm_projects WHERE id = ?", spec.ProjectID)
	if err != nil {
		return err
	}
	if project == nil {
		return domain.Err(404, "project_not_found")
	}
	quota, err := Quota(project)
	if err != nil {
		return err
	}
	totals := zero()
	for _, amounts := range requested {
		for key, value := range amounts {
			if err := addTo(totals, key, value); err != nil {
				return err
			}
		}
	}
	for _, key := range Dimensions {
		if limit, exists := quota[key]; exists && totals[key] > limit {
			return domain.Err(422, "resource_request_exceeds_project_quota")
		}
	}
	pools := map[string]map[string]any{}
	for _, poolID := range sortedKeys(requested) {
		pool, err := tx.One(ctx, "SELECT * FROM jm_pools WHERE id = ?", poolID)
		if err != nil {
			return err
		}
		if pool == nil {
			return domain.Err(422, "resource_pool_not_found")
		}
		pools[poolID] = pool
		capacity, err := PoolCapacity(pool)
		if err != nil {
			return err
		}
		for _, key := range Dimensions {
			if requested[poolID][key] > capacity[key] {
				return domain.Err(422, "resource_request_exceeds_pool")
			}
		}
	}
	if _, possible := assignGPUs(requested, pools, map[string]bool{}); !possible {
		return domain.Err(422, "resource_request_exceeds_pool")
	}
	for _, component := range spec.Components {
		pool := pools[component.Resources.PoolID]
		if !contains(list(pool["sandbox_profiles"]), component.Resources.SandboxProfile) {
			return domain.Err(422, "sandbox_profile_unavailable")
		}
		if component.Resources.GPUCount > 0 && (component.Resources.GPUProfile == nil || !contains(list(pool["gpu_profiles"]), *component.Resources.GPUProfile)) {
			return domain.Err(422, "gpu_profile_unavailable")
		}
	}
	return nil
}

type gpuSlot struct {
	pool       string
	index      int64
	candidates []string
}

func assignGPUs(requests map[string]Amounts, pools map[string]map[string]any, occupied map[string]bool) (map[string][]string, bool) {
	slots := []gpuSlot{}
	for _, pid := range sortedKeys(requests) {
		available := []string{}
		seen := map[string]bool{}
		for _, uuid := range list(pools[pid]["gpu_uuids"]) {
			if !occupied[uuid] && !seen[uuid] {
				available = append(available, uuid)
				seen[uuid] = true
			}
		}
		sort.Strings(available)
		for i := int64(0); i < requests[pid]["gpu_count"]; i++ {
			slots = append(slots, gpuSlot{pid, i, available})
		}
	}
	sort.Slice(slots, func(i, j int) bool {
		if len(slots[i].candidates) != len(slots[j].candidates) {
			return len(slots[i].candidates) < len(slots[j].candidates)
		}
		if slots[i].pool != slots[j].pool {
			return slots[i].pool < slots[j].pool
		}
		return slots[i].index < slots[j].index
	})
	owners := map[string]int{}
	var place func(int, map[string]bool) bool
	place = func(slot int, seen map[string]bool) bool {
		for _, uuid := range slots[slot].candidates {
			if seen[uuid] {
				continue
			}
			seen[uuid] = true
			old, used := owners[uuid]
			if !used || place(old, seen) {
				owners[uuid] = slot
				return true
			}
		}
		return false
	}
	for i := range slots {
		if !place(i, map[string]bool{}) {
			return nil, false
		}
	}
	result := map[string][]string{}
	for pid := range requests {
		result[pid] = []string{}
	}
	for uuid, i := range owners {
		result[slots[i].pool] = append(result[slots[i].pool], uuid)
	}
	for pid := range result {
		sort.Strings(result[pid])
	}
	return result, true
}

func (s *Scheduler) QueueReason(ctx context.Context, jobID string) (map[string]any, error) {
	var reason map[string]any
	e := s.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		job, e := tx.One(ctx, "SELECT queue_reason FROM jm_jobs WHERE id = ?", jobID)
		if e != nil {
			return e
		}
		if job != nil && job["queue_reason"] != nil {
			reason = clone(obj(job["queue_reason"]))
		}
		return nil
	})
	return reason, e
}

// PoolUsedBytes includes retained execution volumes after compute has been released.
func PoolUsedBytes(ctx context.Context, tx *store.Tx, poolID, excludeResourceID string) (int64, error) {
	total := int64(0)
	allocations, e := tx.All(ctx, "SELECT * FROM jm_allocations WHERE pool_id = ?", poolID)
	if e != nil {
		return 0, e
	}
	for _, a := range allocations {
		d := obj(a["details_json"])
		if a["released_at"] == nil || (str(a["state"]) == "RELEASED" && yes(d["retained_disk_charged"]) && !yes(d["storage_deleted"])) {
			amount, e := number(a, "disk_bytes")
			if e != nil {
				return 0, e
			}
			total, e = add(total, amount)
			if e != nil {
				return 0, e
			}
		}
	}
	resources, e := tx.All(ctx, "SELECT * FROM jm_provisioning_resources WHERE retained = ? AND state <> ? AND kind <> ?", true, "deleted", "execution_state")
	if e != nil {
		return 0, e
	}
	for _, r := range resources {
		if str(r["id"]) == excludeResourceID || str(obj(r["details_json"])["pool_id"]) != poolID {
			continue
		}
		n, e := number(r, "size_bytes")
		if e != nil {
			return 0, e
		}
		total, e = add(total, n)
		if e != nil {
			return 0, e
		}
	}
	return total, nil
}

func stableKey(parts ...any) (string, error) {
	data, e := domain.CanonicalJSON(parts)
	if e != nil {
		return "", e
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}
func externalComponent(participant string) (string, error) {
	hash, e := stableKey(participant)
	if e != nil {
		return "", e
	}
	return "participant-" + hash[:40], nil
}
func specFromRow(row map[string]any) (domain.JobSpec, error) {
	data, e := json.Marshal(row["spec_json"])
	if e != nil {
		return domain.JobSpec{}, e
	}
	return domain.DecodeJobSpec(data)
}
func reason(ctx context.Context, tx *store.Tx, job map[string]any, code string, now time.Time, detail map[string]any) error {
	want := clone(detail)
	want["code"] = code
	left, e := domain.CanonicalJSON(job["queue_reason"])
	if e != nil {
		return e
	}
	right, e := domain.CanonicalJSON(want)
	if e != nil {
		return e
	}
	if string(left) == string(right) {
		return nil
	}
	version, e := number(job, "version")
	if e != nil {
		return e
	}
	job["queue_reason"] = want
	job["updated_at"] = now
	job["version"] = version + 1
	return tx.Update(ctx, "jm_jobs", map[string]any{"id": job["id"]}, map[string]any{"queue_reason": want, "updated_at": now, "version": version + 1})
}
func outbox(ctx context.Context, tx *store.Tx, job map[string]any, topic string, payload map[string]any, attemptID any, now time.Time) error {
	attempt, e := number(job, "current_attempt")
	if e != nil {
		return e
	}
	epoch, e := number(job, "epoch")
	if e != nil {
		return e
	}
	version, e := number(job, "version")
	if e != nil {
		return e
	}
	at := str(attemptID)
	if at == "" {
		at = strconv.FormatInt(attempt, 10)
	}
	key := fmt.Sprintf("%s:%s:%s:%d:%d", topic, str(job["id"]), at, epoch, version)
	return tx.Insert(ctx, "jm_outbox", map[string]any{"id": domain.NewID(), "job_id": job["id"], "attempt_id": attemptID, "attempt_number": attempt, "topic": topic, "payload_json": payload, "idempotency_key": key, "state": "pending", "attempts": int64(0), "created_at": now})
}
func event(ctx context.Context, tx *store.Tx, job map[string]any, kind string, payload map[string]any, now time.Time) error {
	row, e := tx.One(ctx, "SELECT COALESCE(MAX(sequence), 0) AS maximum FROM jm_events WHERE job_id = ?", job["id"])
	if e != nil {
		return e
	}
	seq, e := number(row, "maximum")
	if e != nil {
		return e
	}
	return tx.Insert(ctx, "jm_events", map[string]any{"id": domain.NewID(), "job_id": job["id"], "sequence": seq + 1, "kind": kind, "data_json": payload, "version": job["version"], "epoch": job["epoch"], "created_at": now})
}
func eligibility(spec domain.JobSpec, pools map[string]map[string]any) string {
	for _, c := range spec.Components {
		p, ok := pools[c.Resources.PoolID]
		if !ok {
			return "dependencies"
		}
		if yes(p["quarantined"]) {
			return "node_quarantine"
		}
		if !yes(p["healthy"]) {
			return "dependencies"
		}
		if !contains(list(p["sandbox_profiles"]), c.Resources.SandboxProfile) {
			return "unavailable_profile"
		}
		if c.Resources.GPUCount > 0 && (c.Resources.GPUProfile == nil || !contains(list(p["gpu_profiles"]), *c.Resources.GPUProfile)) {
			return "unavailable_profile"
		}
	}
	return ""
}

type storageEntry struct {
	plan                StoragePlan
	resource, ownership map[string]any
}
type blockedJob struct {
	job       map[string]any
	shortages map[string]Amounts
}

func overlaps(request map[string]Amounts, shortage map[string]Amounts) bool {
	for pid, amounts := range shortage {
		for key := range amounts {
			if request[pid][key] > 0 {
				return true
			}
		}
	}
	return false
}
func validKind(kind string) bool {
	length := utf8.RuneCountInString(kind)
	if !utf8.ValidString(kind) || length < 1 || length > 64 {
		return false
	}
	alphanumeric := false
	for _, char := range kind {
		if char == '_' {
			continue
		}
		if !unicode.IsLetter(char) && !unicode.IsNumber(char) {
			return false
		}
		alphanumeric = true
	}
	return alphanumeric
}

func reservedResourceCovered(ctx context.Context, tx *store.Tx, allocation map[string]any) (bool, error) {
	d := obj(allocation["details_json"])
	id := str(d["retained_resource_id"])
	if id == "" {
		return false, nil
	}
	r, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id = ?", id)
	if e != nil || r == nil {
		return false, e
	}
	rd := obj(r["details_json"])
	size, e := number(r, "size_bytes")
	if e != nil {
		return false, e
	}
	disk, e := number(allocation, "disk_bytes")
	if e != nil {
		return false, e
	}
	charged, e := number(rd, "retention_charged_bytes")
	if e != nil {
		return false, e
	}
	return r["job_id"] == allocation["job_id"] && r["attempt_id"] == allocation["attempt_id"] && r["component_id"] == allocation["component_id"] && str(r["kind"]) == "execution_state" && size == disk && rd["pool_id"] == allocation["pool_id"] && yes(rd["covered_by_allocation"]) && charged == disk && !yes(rd["retention_charge_released"]), nil
}

func (s *Scheduler) Schedule(ctx context.Context, limit int) ([]Admission, error) {
	if limit < 1 || limit > 10000 {
		return nil, domain.Err(422, "invalid_schedule_limit")
	}
	if s.DB == nil || s.Clock == nil {
		return nil, errors.New("scheduler requires a database and clock")
	}
	now := s.Clock().UTC()
	admitted := []Admission{}
	e := s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		// All schedulers lock the complete affected pool set, then projects, queued
		// jobs, allocations and GPUs in the same order before evaluating any gang.
		poolRows, e := tx.All(ctx, "SELECT * FROM jm_pools ORDER BY id"+tx.ForUpdate())
		if e != nil {
			return e
		}
		projectRows, e := tx.All(ctx, "SELECT * FROM jm_projects ORDER BY id"+tx.ForUpdate())
		if e != nil {
			return e
		}
		jobs, e := tx.All(ctx, "SELECT * FROM jm_jobs WHERE state = ? ORDER BY created_at, id"+tx.ForUpdate(), "QUEUED")
		if e != nil {
			return e
		}
		allocations, e := tx.All(ctx, "SELECT * FROM jm_allocations WHERE state IN ('RESERVED','ACKNOWLEDGED','STARTING','RUNNING','QUARANTINED','RELEASING') ORDER BY pool_id, id"+tx.ForUpdate())
		if e != nil {
			return e
		}
		gpus, e := tx.All(ctx, "SELECT * FROM jm_gpu_allocations WHERE released_at IS NULL ORDER BY pool_id, gpu_uuid"+tx.ForUpdate())
		if e != nil {
			return e
		}
		pools := map[string]map[string]any{}
		projects := map[string]map[string]any{}
		for _, p := range poolRows {
			pools[str(p["id"])] = p
		}
		for _, p := range projectRows {
			projects[str(p["id"])] = p
		}
		used := map[string]Amounts{}
		projectUsed := map[string]Amounts{}
		activeJobs := map[string]bool{}
		allocationProjects := map[string]string{}
		ensure := func(m map[string]Amounts, id string) Amounts {
			if m[id] == nil {
				m[id] = zero()
			}
			return m[id]
		}
		for _, allocation := range allocations {
			jid := str(allocation["job_id"])
			projectID := allocationProjects[jid]
			if projectID == "" {
				j, e := tx.One(ctx, "SELECT project_id FROM jm_jobs WHERE id = ?", jid)
				if e != nil {
					return e
				}
				if j == nil {
					return errors.New("allocation has no owned job")
				}
				projectID = str(j["project_id"])
				allocationProjects[jid] = projectID
			}
			covered, e := reservedResourceCovered(ctx, tx, allocation)
			if e != nil {
				return e
			}
			for _, key := range Dimensions {
				n, e := number(allocation, key)
				if e != nil {
					return e
				}
				if e = addTo(ensure(used, str(allocation["pool_id"])), key, n); e != nil {
					return e
				}
				if key != "disk_bytes" || !covered {
					if e = addTo(ensure(projectUsed, projectID), key, n); e != nil {
						return e
					}
				}
			}
			activeJobs[jid] = true
		}
		occupied := map[string]bool{}
		for _, gpu := range gpus {
			occupied[str(gpu["gpu_uuid"])] = true
		}
		for _, pid := range sortedKeys(pools) {
			n, e := PoolUsedBytes(ctx, tx, pid, "")
			if e != nil {
				return e
			}
			ensure(used, pid)["disk_bytes"] = n
		}
		blocked := []blockedJob{}
		for _, job := range jobs {
			if len(admitted) >= limit {
				break
			}
			jid := str(job["id"])
			projectID := str(job["project_id"])
			project := projects[projectID]
			if project == nil {
				return errors.New("queued job has no project")
			}
			if activeJobs[jid] {
				if e = reason(ctx, tx, job, "node_quarantine", now, nil); e != nil {
					return e
				}
				continue
			}
			if deadline, ok := store.Time(job["deadline_at"]); ok && !now.Before(deadline) {
				version, e := number(job, "version")
				if e != nil {
					return e
				}
				job["state"] = "CANCELLING"
				job["phase"] = "deadline_exceeded"
				job["updated_at"] = now
				job["version"] = version + 1
				if e = tx.Update(ctx, "jm_jobs", map[string]any{"id": jid}, map[string]any{"state": "CANCELLING", "phase": "deadline_exceeded", "updated_at": now, "version": version + 1}); e != nil {
					return e
				}
				if e = outbox(ctx, tx, job, "fence_stop", map[string]any{"reason": "deadline_exceeded"}, nil, now); e != nil {
					return e
				}
				continue
			}
			if next, ok := store.Time(job["next_attempt_at"]); ok && now.Before(next) {
				if e = reason(ctx, tx, job, "dependencies", now, map[string]any{"available_at": next.Format(time.RFC3339Nano)}); e != nil {
					return e
				}
				continue
			}
			spec, e := specFromRow(job)
			if e != nil {
				return e
			}
			request := RequestedByPool(spec)
			if why := eligibility(spec, pools); why != "" {
				if e = reason(ctx, tx, job, why, now, nil); e != nil {
					return e
				}
				continue
			}
			plans := []StoragePlan{}
			if s.AdmissionStorageTx != nil {
				plans, e = s.AdmissionStorageTx(ctx, tx, clone(job))
			} else if s.AdmissionStorage != nil {
				plans, e = s.AdmissionStorage(ctx, clone(job))
			}
			if e != nil {
				return e
			}
			if len(plans) > 10000 {
				return errors.New("trusted storage plan exceeds its bound")
			}
			components := map[string]domain.ComponentSpec{}
			external := map[string]bool{}
			for _, c := range spec.Components {
				components[c.ComponentID] = c
			}
			for _, p := range spec.Participants {
				if p.Mode == "external" {
					id, e := externalComponent(p.ParticipantID)
					if e != nil {
						return e
					}
					external[id] = true
					if _, exists := components[id]; exists {
						return errors.New("external execution identity collides with a declared component")
					}
				}
			}
			storage := []storageEntry{}
			links := map[string]map[string]any{}
			coveredExisting := int64(0)
			storageUnavailable := false
			seenPlans := map[string]bool{}
			attemptNumber, e := number(job, "current_attempt")
			if e != nil {
				return e
			}
			for _, plan := range plans {
				component, declared := components[plan.ComponentID]
				if !validKind(plan.Kind) || pools[plan.PoolID] == nil || (!declared && !(plan.Kind == "log_budget" && external[plan.ComponentID] && plan.MaxBytes == 1024*1024)) || plan.ExternalID == "" || plan.MaxBytes < 0 {
					return errors.New("trusted admission storage plan differs from its job")
				}
				planKey := plan.Kind + "\x00" + plan.ExternalID
				if seenPlans[planKey] {
					return errors.New("trusted storage planner counted an owned copy twice")
				}
				seenPlans[planKey] = true
				if plan.Kind == "execution_state" && !plan.CoveredByAllocation {
					return errors.New("execution state must be backed by its immutable allocation")
				}
				if plan.CoveredByAllocation && (!declared || plan.Kind != "execution_state" || plan.PoolID != component.Resources.PoolID || plan.MaxBytes != component.Resources.DiskBytes || !yes(plan.Details["covered_by_allocation"])) {
					return errors.New("covered state budget differs from its immutable allocation")
				}
				pool := pools[plan.PoolID]
				if !yes(pool["healthy"]) || yes(pool["quarantined"]) {
					if e = reason(ctx, tx, job, "node_quarantine", now, map[string]any{"pool_id": plan.PoolID}); e != nil {
						return e
					}
					storageUnavailable = true
					break
				}
				resource, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE kind = ? AND external_id = ?", plan.Kind, plan.ExternalID)
				if e != nil {
					return e
				}
				ownership := map[string]any{"job_id": jid, "component_id": plan.ComponentID, "kind": plan.Kind}
				if resource != nil {
					a, e := domain.CanonicalJSON(resource["ownership_json"])
					if e != nil {
						return e
					}
					b, e := domain.CanonicalJSON(ownership)
					if e != nil {
						return e
					}
					if str(resource["job_id"]) != jid || string(a) != string(b) {
						return errors.New("storage admission cannot adopt foreign resources")
					}
					detail := obj(resource["details_json"])
					if _, charged := detail["retention_charged_bytes"]; charged && !yes(detail["retention_charge_released"]) {
						lifetime := plan.Kind == "exchange_blob_budget"
						if lifetime {
							if e = verifyLifetimeBlob(job, spec, plan, resource); e != nil {
								return e
							}
						}
						oldAttempt := attemptNumber
						if detail["attempt_number"] != nil {
							oldAttempt, e = ExactInteger(detail["attempt_number"])
							if e != nil {
								return e
							}
						}
						if str(detail["pool_id"]) != plan.PoolID || (!lifetime && oldAttempt != attemptNumber) {
							return errors.New("storage admission resource changed its binding")
						}
						if pointer := resourcePointer(plan.Kind); pointer != "" {
							if links[plan.ComponentID] == nil {
								links[plan.ComponentID] = map[string]any{}
							}
							links[plan.ComponentID][pointer] = resource["id"]
						}
						if plan.CoveredByAllocation {
							coveredExisting, e = add(coveredExisting, plan.MaxBytes)
							if e != nil {
								return e
							}
						}
						continue
					}
				}
				storage = append(storage, storageEntry{plan, resource, ownership})
				if !plan.CoveredByAllocation {
					if e = addTo(ensure(request, plan.PoolID), "disk_bytes", plan.MaxBytes); e != nil {
						return e
					}
				}
			}
			if storageUnavailable {
				continue
			}
			totals := zero()
			for _, amounts := range request {
				for key, n := range amounts {
					if e = addTo(totals, key, n); e != nil {
						return e
					}
				}
			}
			quota, e := Quota(project)
			if e != nil {
				return e
			}
			retained, e := number(project, "retained_bytes")
			if e != nil {
				return e
			}
			if retained < coveredExisting {
				return errors.New("retained storage accounting is inconsistent")
			}
			if e = addTo(totals, "disk_bytes", retained-coveredExisting); e != nil {
				return e
			}
			extra := int64(0)
			for _, entry := range storage {
				extra, e = add(extra, entry.plan.MaxBytes)
				if e != nil {
					return e
				}
			}
			retainedTotal, e := add(retained, extra)
			if e != nil {
				return e
			}
			if limit, ok := quota["retained_bytes"]; ok && retainedTotal > limit {
				if e = reason(ctx, tx, job, "quota", now, nil); e != nil {
					return e
				}
				continue
			}
			overQuota := false
			for _, key := range Dimensions {
				n, e := add(ensure(projectUsed, projectID)[key], totals[key])
				if e != nil {
					return e
				}
				if limit, ok := quota[key]; ok && n > limit {
					overQuota = true
				}
			}
			if limit, ok := quota["max_running_jobs"]; ok {
				ids := map[string]bool{}
				for _, a := range allocations {
					if allocationProjects[str(a["job_id"])] == projectID {
						ids[str(a["job_id"])] = true
					}
				}
				if int64(len(ids)) >= limit {
					overQuota = true
				}
			}
			if overQuota {
				if e = reason(ctx, tx, job, "quota", now, nil); e != nil {
					return e
				}
				continue
			}
			shortages := map[string]Amounts{}
			for pid, amounts := range request {
				cap, e := PoolCapacity(pools[pid])
				if e != nil {
					return e
				}
				for _, key := range Dimensions {
					available := cap[key] - ensure(used, pid)[key]
					if amounts[key] > available {
						if shortages[pid] == nil {
							shortages[pid] = Amounts{}
						}
						shortages[pid][key] = amounts[key] - available
					}
				}
			}
			assigned, ok := assignGPUs(request, pools, occupied)
			if !ok {
				for pid, amounts := range request {
					if amounts["gpu_count"] > 0 {
						if shortages[pid] == nil {
							shortages[pid] = Amounts{}
						}
						shortages[pid]["gpu_count"] = 1
					}
				}
			}
			if len(shortages) > 0 {
				if e = reason(ctx, tx, job, "capacity", now, map[string]any{"shortages": shortages}); e != nil {
					return e
				}
				blocked = append(blocked, blockedJob{job, shortages})
				continue
			}
			protected := false
			for _, older := range blocked {
				count, e := number(older.job, "backfill_count")
				if e != nil {
					return e
				}
				if count >= MaxBackfills && overlaps(request, older.shortages) {
					protected = true
					break
				}
			}
			if protected {
				if e = reason(ctx, tx, job, "capacity", now, map[string]any{"protection": "older_request"}); e != nil {
					return e
				}
				continue
			}
			attempt, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE job_id = ? AND number = ?"+tx.ForUpdate(), jid, attemptNumber)
			if e != nil {
				return e
			}
			if attempt == nil {
				return errors.New("queued job is missing its durable attempt")
			}
			epoch, e := number(job, "epoch")
			if e != nil {
				return e
			}
			epoch++
			version, e := number(job, "version")
			if e != nil {
				return e
			}
			version++
			job["epoch"] = epoch
			job["version"] = version
			job["state"] = "PROVISIONING"
			job["phase"] = "reserving"
			job["queue_reason"] = nil
			job["backfill_count"] = int64(0)
			job["updated_at"] = now
			update := map[string]any{"epoch": epoch, "version": version, "state": "PROVISIONING", "phase": "reserving", "queue_reason": nil, "backfill_count": int64(0), "updated_at": now}
			if job["deadline_at"] == nil {
				deadline := now.Add(time.Duration(spec.MaxDurationSeconds) * time.Second)
				job["deadline_at"] = deadline
				update["deadline_at"] = deadline
			}
			if e = tx.Update(ctx, "jm_jobs", map[string]any{"id": jid}, update); e != nil {
				return e
			}
			attemptID := str(attempt["id"])
			if e = tx.Update(ctx, "jm_attempts", map[string]any{"id": attemptID}, map[string]any{"epoch": epoch, "state": "PROVISIONING", "termination_confirmed": false}); e != nil {
				return e
			}
			created := []map[string]any{}
			for _, component := range spec.Components {
				r := component.Resources
				a := map[string]any{"id": domain.NewID(), "job_id": jid, "attempt_id": attemptID, "component_id": component.ComponentID, "pool_id": r.PoolID, "cpu_millicores": r.CPUMillicores, "memory_bytes": r.MemoryBytes, "disk_bytes": r.DiskBytes, "gpu_count": r.GPUCount, "state": "RESERVED", "epoch": epoch, "acknowledged": false, "termination_confirmed": false, "created_at": now, "details_json": map[string]any{"node_id": pools[r.PoolID]["node_id"]}}
				if e = tx.Insert(ctx, "jm_allocations", a); e != nil {
					return e
				}
				for i := int64(0); i < r.GPUCount; i++ {
					uuid := assigned[r.PoolID][0]
					assigned[r.PoolID] = assigned[r.PoolID][1:]
					if e = tx.Insert(ctx, "jm_gpu_allocations", map[string]any{"id": domain.NewID(), "pool_id": r.PoolID, "gpu_uuid": uuid, "allocation_id": a["id"]}); e != nil {
						return e
					}
					occupied[uuid] = true
				}
				for key, n := range values(r) {
					if e = addTo(ensure(used, r.PoolID), key, n); e != nil {
						return e
					}
					if e = addTo(ensure(projectUsed, projectID), key, n); e != nil {
						return e
					}
				}
				created = append(created, a)
				allocations = append(allocations, a)
				allocationProjects[jid] = projectID
			}
			for _, entry := range storage {
				plan := entry.plan
				resource := entry.resource
				if resource == nil {
					id, e := stableKey("resource", jid, plan.Kind, plan.ExternalID)
					if e != nil {
						return e
					}
					details := clone(plan.Details)
					details["pool_id"] = plan.PoolID
					details["component_id"] = plan.ComponentID
					details["attempt_number"] = attemptNumber
					details["reservation_max_bytes"] = plan.MaxBytes
					resource = map[string]any{"id": id[:32], "job_id": jid, "attempt_id": attemptID, "component_id": plan.ComponentID, "kind": plan.Kind, "external_id": plan.ExternalID, "ownership_json": entry.ownership, "details_json": details, "state": "planned", "retained": true, "created_at": now, "updated_at": now}
					if e = tx.Insert(ctx, "jm_provisioning_resources", resource); e != nil {
						return e
					}
				}
				resource["attempt_id"] = attemptID
				if e = tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": resource["id"]}, map[string]any{"attempt_id": attemptID}); e != nil {
					return e
				}
				if e = ReserveStorage(ctx, tx, resource, project, plan.MaxBytes, pools[plan.PoolID]); e != nil {
					return e
				}
				if !plan.CoveredByAllocation {
					if e = addTo(ensure(used, plan.PoolID), "disk_bytes", plan.MaxBytes); e != nil {
						return e
					}
				}
				if pointer := resourcePointer(plan.Kind); pointer != "" {
					if links[plan.ComponentID] == nil {
						links[plan.ComponentID] = map[string]any{}
					}
					links[plan.ComponentID][pointer] = resource["id"]
				}
			}
			for _, componentLinks := range links {
				for _, resourceID := range componentLinks {
					resource, e := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id = ?", resourceID)
					if e != nil {
						return e
					}
					if resource == nil {
						return errors.New("prepaid resource disappeared")
					}
					if resource["attempt_id"] != nil && str(resource["attempt_id"]) != attemptID {
						return errors.New("prepaid budget belongs to another attempt")
					}
					if e = tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": resourceID}, map[string]any{"attempt_id": attemptID}); e != nil {
						return e
					}
				}
			}
			ids := []string{}
			for _, allocation := range created {
				d := clone(obj(allocation["details_json"]))
				for key, value := range links[str(allocation["component_id"])] {
					d[key] = value
				}
				allocation["details_json"] = d
				if e = tx.Update(ctx, "jm_allocations", map[string]any{"id": allocation["id"]}, map[string]any{"details_json": d}); e != nil {
					return e
				}
				if d["retained_resource_id"] != nil {
					disk, e := number(allocation, "disk_bytes")
					if e != nil {
						return e
					}
					projectUsed[projectID]["disk_bytes"] -= disk
				}
				ids = append(ids, str(allocation["id"]))
			}
			if e = outbox(ctx, tx, job, "dispatch", map[string]any{"epoch": epoch}, attemptID, now); e != nil {
				return e
			}
			if e = event(ctx, tx, job, "admitted", map[string]any{"epoch": epoch, "allocations": len(created)}, now); e != nil {
				return e
			}
			for _, older := range blocked {
				if overlaps(request, older.shortages) {
					count, e := number(older.job, "backfill_count")
					if e != nil {
						return e
					}
					v, e := number(older.job, "version")
					if e != nil {
						return e
					}
					older.job["backfill_count"] = count + 1
					older.job["version"] = v + 1
					older.job["updated_at"] = now
					if e = tx.Update(ctx, "jm_jobs", map[string]any{"id": older.job["id"]}, map[string]any{"backfill_count": count + 1, "version": v + 1, "updated_at": now}); e != nil {
						return e
					}
				}
			}
			admitted = append(admitted, Admission{jid, attemptID, epoch, ids})
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	return admitted, nil
}

func resourcePointer(kind string) string {
	switch kind {
	case "collection_budget":
		return "collection_resource_id"
	case "log_budget":
		return "log_resource_id"
	case "execution_state":
		return "retained_resource_id"
	}
	return ""
}

// ReserveStorage must run while the caller holds Pool -> Project -> Job locks.
func ReserveStorage(ctx context.Context, tx *store.Tx, resource, project map[string]any, maximum int64, pool map[string]any) error {
	if maximum < 0 {
		return domain.Err(422, "invalid_retained_size")
	}
	if str(resource["state"]) == "deleted" || resource["deleted_at"] != nil {
		return domain.Err(409, "retained_resource_already_deleted")
	}
	details := clone(obj(resource["details_json"]))
	if pid := str(details["pool_id"]); pid != "" && (pool == nil || str(pool["id"]) != pid) {
		return domain.Err(409, "retained_resource_pool_context_required")
	}
	if yes(details["retention_charge_released"]) {
		return domain.Err(409, "retained_resource_charge_conflict")
	}
	if charge, exists := details["retention_charged_bytes"]; exists {
		charged, e := ExactInteger(charge)
		if e != nil {
			return e
		}
		settled, explicit := details["retention_charge_settled"].(bool)
		_, reserved := details["retention_reservation_bytes"]
		if !explicit {
			settled = !reserved
		}
		if settled {
			if charged > maximum {
				return domain.Err(409, "retained_resource_exceeds_reservation")
			}
			return nil
		}
		reservedAmount, e := ExactInteger(details["retention_reservation_bytes"])
		if e != nil {
			return e
		}
		if reservedAmount != maximum {
			return domain.Err(409, "retained_resource_reservation_conflict")
		}
		return nil
	}
	if pool != nil && str(resource["kind"]) != "execution_state" {
		used, e := PoolUsedBytes(ctx, tx, str(pool["id"]), str(resource["id"]))
		if e != nil {
			return e
		}
		total, e := add(used, maximum)
		if e != nil {
			return e
		}
		cap, e := number(pool, "disk_bytes")
		if e != nil {
			return e
		}
		if total > cap {
			return domain.Err(409, "retained_pool_storage_unavailable")
		}
	}
	retained, e := number(project, "retained_bytes")
	if e != nil {
		return e
	}
	total, e := add(retained, maximum)
	if e != nil {
		return e
	}
	q := obj(project["quotas_json"])
	limit := q["retained_bytes"]
	if limit == nil {
		limit = q["disk_bytes"]
	}
	if limit == nil {
		limit = project["quota_disk_bytes"]
	}
	if limit != nil {
		cap, e := ExactInteger(limit)
		if e != nil {
			return e
		}
		if total > cap {
			return domain.Err(409, "retained_storage_quota_exceeded")
		}
	}
	version, e := number(project, "version")
	if e != nil {
		return e
	}
	project["retained_bytes"] = total
	project["version"] = version + 1
	if e = tx.Update(ctx, "jm_projects", map[string]any{"id": project["id"]}, map[string]any{"retained_bytes": total, "version": version + 1}); e != nil {
		return e
	}
	details["retention_charged_bytes"] = maximum
	details["retention_reservation_bytes"] = maximum
	details["retention_charge_settled"] = false
	details["retention_charge_released"] = false
	resource["retained"] = true
	resource["size_bytes"] = maximum
	resource["details_json"] = details
	return tx.Update(ctx, "jm_provisioning_resources", map[string]any{"id": resource["id"]}, map[string]any{"retained": true, "size_bytes": maximum, "details_json": details})
}

func verifyLifetimeBlob(job map[string]any, spec domain.JobSpec, plan StoragePlan, resource map[string]any) error {
	owner := domain.ComponentSpec{}
	for _, c := range spec.Components {
		if c.Role == "owner" {
			owner = c
			break
		}
	}
	checkpoint := owner.Resources.DiskBytes
	// Use exact arbitrary-size arithmetic before narrowing a namespace cap.
	rounds := big.NewInt(spec.TargetRound)
	scale := new(big.Int).Mul(rounds, big.NewInt(1+int64(len(spec.Participants))))
	scale.Add(scale, big.NewInt(1))
	quota := new(big.Int).Mul(big.NewInt(checkpoint), scale)
	principal := new(big.Int).Mul(big.NewInt(checkpoint), new(big.Int).Add(rounds, big.NewInt(1)))
	if !quota.IsInt64() || !principal.IsInt64() || quota.Sign() <= 0 {
		return errors.New("Exchange checkpoint budget exceeds the supported byte range")
	}
	digest, e := spec.Digest()
	if e != nil {
		return e
	}
	id, e := stableKey("resource", str(job["id"]), "exchange_blob_budget", "hf2l-exchange-blobs://"+str(job["id"]))
	if e != nil {
		return e
	}
	d := obj(resource["details_json"])
	fields := map[string]int64{"quota_bytes": quota.Int64(), "principal_quota_bytes": principal.Int64(), "reservation_max_bytes": quota.Int64(), "retention_charged_bytes": quota.Int64(), "retention_reservation_bytes": quota.Int64()}
	for key, want := range fields {
		have, e := number(d, key)
		if e != nil || have != want {
			return errors.New("lifetime Exchange allowance changed its immutable binding")
		}
	}
	size, e := number(resource, "size_bytes")
	if e != nil {
		return e
	}
	if plan.MaxBytes != quota.Int64() || plan.ComponentID != owner.ComponentID || plan.ExternalID != "hf2l-exchange-blobs://"+str(job["id"]) || str(resource["id"]) != id[:32] || size != quota.Int64() || str(d["spec_digest"]) != digest || str(d["pool_id"]) != plan.PoolID {
		return errors.New("lifetime Exchange allowance changed its immutable binding")
	}
	return nil
}

// Release frees compute only after durable revocation and termination are proven.
// Retained disk remains charged until its separate owned-storage deletion receipt.
func (s *Scheduler) Release(ctx context.Context, allocationID string) error {
	now := s.Clock().UTC()
	return s.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		observed, e := tx.One(ctx, "SELECT * FROM jm_allocations WHERE id = ?", allocationID)
		if e != nil {
			return e
		}
		if observed == nil {
			return domain.Err(404, "allocation_not_found")
		}
		if _, e = tx.One(ctx, "SELECT * FROM jm_pools WHERE id = ?"+tx.ForUpdate(), observed["pool_id"]); e != nil {
			return e
		}
		job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id = ?", observed["job_id"])
		if e != nil {
			return e
		}
		if job == nil {
			return errors.New("allocation has no owned job")
		}
		if _, e = tx.One(ctx, "SELECT * FROM jm_projects WHERE id = ?"+tx.ForUpdate(), job["project_id"]); e != nil {
			return e
		}
		if _, e = tx.One(ctx, "SELECT * FROM jm_jobs WHERE id = ?"+tx.ForUpdate(), job["id"]); e != nil {
			return e
		}
		allocation, e := tx.One(ctx, "SELECT * FROM jm_allocations WHERE id = ?"+tx.ForUpdate(), allocationID)
		if e != nil {
			return e
		}
		if allocation["released_at"] != nil {
			return nil
		}
		attempt, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE id = ?"+tx.ForUpdate(), allocation["attempt_id"])
		if e != nil {
			return e
		}
		if attempt == nil || !yes(attempt["revocation_confirmed"]) || !yes(attempt["termination_confirmed"]) || !yes(allocation["termination_confirmed"]) {
			return domain.Err(409, "allocation_termination_unconfirmed")
		}
		details := clone(obj(allocation["details_json"]))
		update := map[string]any{"state": "RELEASED", "released_at": now}
		if !yes(details["storage_deleted"]) {
			resourceID := str(details["retained_resource_id"])
			if resourceID != "" {
				resource, err := tx.One(ctx, "SELECT * FROM jm_provisioning_resources WHERE id = ?"+tx.ForUpdate(), resourceID)
				if err != nil {
					return err
				}
				if err = verifyRetainedExecution(allocation, resource); err != nil {
					return err
				}
				details["retained_disk_charged"] = true
				details["storage_deleted"] = false
				update["details_json"] = details
			} else if yes(allocation["acknowledged"]) || yes(details["retained_disk_charged"]) {
				return domain.Err(409, "retained_resource_charge_unconfirmed")
			}
		}
		if e = tx.Update(ctx, "jm_allocations", map[string]any{"id": allocationID}, update); e != nil {
			return e
		}
		_, e = tx.Exec(ctx, "UPDATE jm_gpu_allocations SET released_at = ? WHERE allocation_id = ? AND released_at IS NULL", now, allocationID)
		return e
	})
}

// ReleaseAllocation is a compatibility spelling for controller composition.
func (s *Scheduler) ReleaseAllocation(ctx context.Context, allocationID string) error {
	return s.Release(ctx, allocationID)
}

// Live reports the persisted allocation states that consume compute capacity.
func Live(state string) bool { return contains(LiveAllocationStates, strings.ToUpper(state)) }

// A stopped execution can still own a full filesystem. This charge is separate
// from CPU/RAM release and survives until the owned deletion receipt is durable.
func verifyRetainedExecution(allocation, resource map[string]any) error {
	if resource == nil {
		return domain.Err(409, "retained_resource_charge_unconfirmed")
	}
	details := obj(resource["details_json"])
	ownership := obj(resource["ownership_json"])
	disk, err := number(allocation, "disk_bytes")
	if err != nil {
		return err
	}
	size, err := number(resource, "size_bytes")
	if err != nil {
		return err
	}
	charged, err := number(details, "retention_charged_bytes")
	if err != nil {
		return err
	}
	if resource["job_id"] != allocation["job_id"] || resource["attempt_id"] != allocation["attempt_id"] ||
		resource["component_id"] != allocation["component_id"] || str(resource["kind"]) != "execution_state" ||
		ownership["job_id"] != allocation["job_id"] || !yes(resource["retained"]) ||
		str(resource["state"]) == "deleted" || resource["deleted_at"] != nil || yes(details["retention_charge_released"]) ||
		size != disk || charged != disk || (details["pool_id"] != nil && details["pool_id"] != allocation["pool_id"]) {
		return domain.Err(409, "retained_resource_charge_unconfirmed")
	}
	return nil
}
