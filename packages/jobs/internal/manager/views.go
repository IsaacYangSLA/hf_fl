package manager

import (
	"context"
	"math"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func (m *Manager) allowed(job, member Object) []string {
	actions := []string{}
	role := text(member["role"])
	purged := job["purged_at"] != nil
	if (role == "operator" || role == "admin") && !purged {
		state := text(job["state"])
		if !domain.IsTerminal(state) && state != "CANCELLING" {
			actions = append(actions, "cancel")
		}
		if state == "FAILED" && !expired(job["deadline_at"], m.now()) && !has([]any{"purge_pending", "expiry_pending", "expired"}, text(job["cleanup_status"])) && !expired(job["artifacts_expire_at"], m.now()) {
			actions = append(actions, "retry")
		}
		if state == "NEEDS_ATTENTION" {
			actions = append(actions, "reconcile")
		}
	}
	if role == "admin" {
		actions = append(actions, "manage_members")
		if domain.IsTerminal(text(job["state"])) && !purged {
			actions = append(actions, "purge")
		}
	}
	return actions
}
func (m *Manager) jobView(ctx context.Context, tx *store.Tx, job, member Object, detail bool) (Object, error) {
	value := Object{}
	for _, k := range []string{"id", "project_id", "name", "state", "phase", "queue_reason", "version", "current_attempt", "target_round", "current_round", "error_code", "outcome_reason", "spec_hash"} {
		value[k] = job[k]
	}
	for _, k := range []string{"created_at", "updated_at", "deadline_at", "terminated_at"} {
		value[k] = iso(job[k])
	}
	value["retention"] = Object{"expires_at": iso(job["artifacts_expire_at"]), "expired": expired(job["artifacts_expire_at"], m.now()), "cleanup_status": job["cleanup_status"], "purged_at": iso(job["purged_at"])}
	value["role"] = member["role"]
	actions := m.allowed(job, member)
	value["allowed_actions"] = actions
	spec := obj(job["spec_json"])
	if job["purged_at"] != nil {
		value["name"] = "Purged job"
		value["purged"] = true
		return value, nil
	}
	summary := Object{"cpu_millicores": int64(0), "memory_bytes": int64(0), "disk_bytes": int64(0), "gpu_count": int64(0)}
	for _, v := range arr(spec["components"]) {
		resources := obj(obj(v)["resources"])
		for key := range summary {
			summary[key] = number(summary[key]) + number(resources[key])
		}
	}
	value["resource_summary"] = summary
	value["participants_count"] = len(arr(spec["participants"]))
	value["first_reserved_at"] = nil
	if deadline, ok := store.Time(job["deadline_at"]); ok {
		value["first_reserved_at"] = iso(deadline.Add(-time.Duration(number(spec["max_duration_seconds"])) * time.Second))
	}
	if !detail {
		return value, nil
	}
	clean := copyObject(spec)
	delete(clean, "secret_refs")
	value["spec"] = clean
	bindings, err := tx.All(ctx, "SELECT * FROM jm_participant_bindings WHERE project_id = ?", job["project_id"])
	if err != nil {
		return nil, err
	}
	byID := map[string]Object{}
	for _, b := range bindings {
		byID[text(b["id"])] = b
	}
	participants := []Object{}
	for _, p := range arr(spec["participants"]) {
		part := copyObject(obj(p))
		binding := byID[text(part["dataset_binding"])]
		var node any
		if binding != nil && flag(binding["enabled"]) && binding["participant_id"] == part["participant_id"] {
			node = binding["node_id"]
		}
		part["node_id"] = node
		part["allowed_actions"] = []string{}
		if text(part["mode"]) == "external" && text(node) != "" && roleLevel(text(member["role"])) >= 2 && has([]any{"QUEUED", "PROVISIONING", "STARTING", "RUNNING"}, text(job["state"])) && !expired(job["deadline_at"], m.now()) {
			part["allowed_actions"] = []string{"enroll_participant"}
			if !has(actions, "enroll_participant") {
				actions = append(actions, "enroll_participant")
			}
		}
		participants = append(participants, part)
	}
	value["participants"] = participants
	value["allowed_actions"] = actions
	resources := []Object{}
	for _, c := range arr(spec["components"]) {
		component := obj(c)
		res := copyObject(obj(component["resources"]))
		res["component_id"] = component["component_id"]
		res["role"] = component["role"]
		resources = append(resources, res)
	}
	value["resources"] = resources
	if err = m.observations(ctx, tx, job, value, participants); err != nil {
		return nil, err
	}
	return value, nil
}
func (m *Manager) safeReport(value any) Object {
	report := obj(value)
	metrics := Object{}
	raw := obj(report["metrics"])
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i >= 32 {
			break
		}
		if badText(k, 64) {
			continue
		}
		n := decimal(raw[k])
		if !math.IsNaN(n) && !math.IsInf(n, 0) {
			metrics[k] = raw[k]
		}
	}
	readiness := text(report["readiness"])
	if !has([]any{"initializing", "waiting", "ready", "training", "finished", "failed"}, readiness) {
		readiness = "not_observed"
	}
	var observed any
	if raw, ok := report["observed_at"].(string); ok && len(raw) <= 128 {
		if t, e := time.Parse(time.RFC3339Nano, raw); e == nil {
			observed = t.UTC()
		}
	}
	freshness := "not_observed"
	if t, ok := store.Time(observed); ok {
		age := m.now().Sub(t)
		freshness = "current"
		if age > 300*time.Second {
			freshness = "stale"
		} else if age < -30*time.Second {
			freshness = "clock_skew"
		}
	}
	status := "not_observed"
	if len(metrics) > 0 {
		status = "observed"
	}
	out := Object{"metrics": metrics, "metrics_status": status, "readiness": readiness, "observed_at": iso(observed), "freshness": freshness}
	if n, ok := strictInt(report["current_round"]); ok && n >= 0 {
		out["reported_round"] = n
	}
	if v := text(report["phase"]); has([]any{"fetching", "building", "initializing", "aggregating", "waiting_participants", "training", "publishing", "collecting_results"}, v) {
		out["phase"] = v
	}
	if v := text(report["publication_status"]); has([]any{"none", "absent", "confirmed", "published", "unknown", "publishing", "ambiguous", "not_observed"}, v) {
		out["publication_status"] = v
	}
	return out
}
func (m *Manager) attemptComponents(job, attempt Object, observed bool) []Object {
	reports := obj(obj(attempt["details_json"])["components"])
	if !observed {
		reports = Object{}
	}
	components := []Object{}
	for i, c := range arr(obj(job["spec_json"])["components"]) {
		if i >= 1024 {
			break
		}
		spec := obj(c)
		v := m.safeReport(reports[text(spec["component_id"])])
		v["component_id"] = spec["component_id"]
		v["role"] = spec["role"]
		v["participant_id"] = spec["participant_id"]
		components = append(components, v)
	}
	return components
}
func (m *Manager) observations(ctx context.Context, tx *store.Tx, job, value Object, participants []Object) error {
	attempt, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE job_id = ? AND number = ?", job["id"], job["current_attempt"])
	if e != nil {
		return e
	}
	if attempt == nil {
		attempt = Object{}
	}
	comps := m.attemptComponents(job, attempt, attempt["id"] != nil && number(attempt["epoch"]) == number(job["epoch"]))
	byID := map[string]Object{}
	owner := m.safeReport(nil)
	for _, c := range comps {
		byID[text(c["component_id"])] = c
		if text(c["role"]) == "owner" {
			owner = c
		}
	}
	value["metrics"] = owner["metrics"]
	value["progress"] = Object{"attempt_id": attempt["id"], "epoch": attempt["epoch"], "metrics": owner["metrics"], "metrics_status": owner["metrics_status"], "observed_at": owner["observed_at"], "freshness": owner["freshness"], "components": comps}
	alloc := []Object{}
	if attempt["id"] != nil {
		rows, err := tx.All(ctx, "SELECT * FROM jm_allocations WHERE job_id = ? AND attempt_id = ? AND epoch = ? ORDER BY component_id", job["id"], attempt["id"], attempt["epoch"])
		if err != nil {
			return err
		}
		for _, r := range rows {
			if byID[text(r["component_id"])] == nil {
				continue
			}
			v := Object{}
			for _, k := range []string{"component_id", "pool_id", "state", "acknowledged", "termination_confirmed", "cpu_millicores", "memory_bytes", "disk_bytes", "gpu_count"} {
				v[k] = r[k]
			}
			alloc = append(alloc, v)
		}
	}
	value["allocations"] = alloc
	enrollments, err := tx.All(ctx, "SELECT * FROM jm_provisioning_resources WHERE job_id = ? AND kind = ?", job["id"], "external_enrollment")
	if err != nil {
		return err
	}
	external := map[string]Object{}
	for _, entry := range enrollments {
		data := obj(entry["details_json"])
		own := obj(entry["ownership_json"])
		pid := text(data["participant_id"])
		if pid != "" && own["job_id"] == job["id"] && text(own["participant_id"]) == pid && attempt["id"] != nil && entry["attempt_id"] == attempt["id"] && number(data["epoch"]) == number(attempt["epoch"]) {
			external[pid] = data
		}
	}
	for _, p := range participants {
		report := byID[text(p["component_id"])]
		if text(p["mode"]) == "managed" && report != nil {
			for _, k := range []string{"readiness", "metrics", "observed_at", "freshness"} {
				p[k] = report[k]
			}
			continue
		}
		p["readiness"] = "not_observed"
		p["metrics"] = Object{}
		p["observed_at"] = nil
		p["freshness"] = "not_observed"
		data := external[text(p["participant_id"])]
		if text(p["mode"]) != "external" || data == nil || data["dataset_binding"] != p["dataset_binding"] || data["node_id"] != p["node_id"] {
			continue
		}
		status := text(data["status"])
		if has([]any{"enrolled", "dispatching", "preparing", "assigned", "stopped", "purging", "purged", "failed", "needs_attention"}, status) {
			p["status"] = status
			p["enrollment"] = Object{"status": status, "node_id": p["node_id"], "attempt_id": attempt["id"], "epoch": data["epoch"]}
		}
		phase := text(data["phase"])
		if has([]any{"running", "waiting_initialization", "waiting_for_model", "training", "publishing", "completed", "retry", "needs_attention", "stopped"}, phase) {
			r := m.safeReport(Object{"observed_at": data["last_heartbeat"]})
			p["readiness"] = phase
			p["observed_at"] = r["observed_at"]
			p["freshness"] = r["freshness"]
		}
	}
	spaces, err := tx.All(ctx, "SELECT * FROM jm_provisioning_resources WHERE job_id = ? AND kind = ? ORDER BY created_at", job["id"], "exchange_space")
	if err != nil {
		return err
	}
	owned := []Object{}
	for _, space := range spaces {
		if obj(space["ownership_json"])["job_id"] == job["id"] && text(space["state"]) != "deleted" && text(space["external_id"]) != "" && utf8.RuneCountInString(text(space["external_id"])) <= 256 {
			owned = append(owned, space)
		}
	}
	value["space_id"] = nil
	if len(owned) == 1 {
		value["space_id"] = owned[0]["external_id"]
	}
	return nil
}
func (m *Manager) GetJob(ctx context.Context, actor, id string) (Object, error) {
	var result Object
	e := m.withJob(ctx, actor, id, "reader", false, func(tx *store.Tx, job, member Object) error {
		var e error
		result, e = m.jobView(ctx, tx, job, member, true)
		return e
	})
	return result, e
}
func (m *Manager) ListAttempts(ctx context.Context, actor, id string) (Object, error) {
	result := Object{"items": []Object{}}
	e := m.withJob(ctx, actor, id, "reader", false, func(tx *store.Tx, job, member Object) error {
		rows, e := tx.All(ctx, "SELECT * FROM jm_attempts WHERE job_id = ? ORDER BY number", id)
		if e != nil {
			return e
		}
		items := []Object{}
		for _, r := range rows {
			v := Object{}
			for _, k := range []string{"id", "number", "epoch", "state", "error_code", "revocation_confirmed", "termination_confirmed", "publication_status"} {
				v[k] = r[k]
			}
			for _, k := range []string{"started_at", "ended_at", "created_at", "heartbeat_at"} {
				v[k] = iso(r[k])
			}
			v["resources"] = r["resources_json"]
			v["components"] = m.attemptComponents(job, r, true)
			items = append(items, v)
		}
		result["items"] = items
		return nil
	})
	return result, e
}
func (m *Manager) VisibleRevision(ctx context.Context, actor string) (string, error) {
	if e := principal(actor); e != nil {
		return "", e
	}
	values := []any{}
	e := m.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		rows, e := tx.All(ctx, `SELECT j.id,j.version,j.purged_at,m.role,e.sequence,l.latest_log_at
   FROM jm_jobs j JOIN jm_job_members m ON m.job_id=j.id AND m.principal_id=?
   LEFT JOIN (SELECT x.job_id,MAX(x.sequence) AS sequence FROM jm_events x JOIN jm_job_members a ON a.job_id=x.job_id AND a.principal_id=? GROUP BY x.job_id) e ON e.job_id=j.id
   LEFT JOIN (SELECT x.job_id,MAX(x.created_at) AS latest_log_at FROM jm_log_chunks x JOIN jm_job_members a ON a.job_id=x.job_id AND a.principal_id=? GROUP BY x.job_id) l ON l.job_id=j.id
   ORDER BY j.id`, actor, actor, actor)
		if e != nil {
			return e
		}
		for _, r := range rows {
			values = append(values, []any{r["id"], r["version"], r["role"], number(r["sequence"]), iso(r["latest_log_at"]), iso(r["purged_at"])})
		}
		return nil
	})
	if e != nil {
		return "", e
	}
	return hash(values)
}
