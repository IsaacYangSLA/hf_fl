package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

func objMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}
func strValue(v any) string { s, _ := v.(string); return s }
func intValue(v any) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	case json.Number:
		i, _ := n.Int64()
		return i
	}
	return 0
}
func boolValue(v any) bool { b, _ := v.(bool); return b }
func cfgID(v any) (string, error) {
	s, ok := v.(string)
	if !ok || domain.ValidateIdentifier(s) != nil {
		return "", config.Invalid()
	}
	return s, nil
}
func cfgText(m map[string]any, k string) (string, error) {
	v, ok := m[k]
	if !ok {
		return "", config.Invalid()
	}
	return config.Text(v, 4096)
}
func stringsValue(v any) ([]string, error) {
	switch a := v.(type) {
	case []string:
		return a, nil
	case []any:
		r := []string{}
		for _, x := range a {
			s, ok := x.(string)
			if !ok {
				return nil, config.Invalid()
			}
			r = append(r, s)
		}
		return r, nil
	}
	return nil, config.Invalid()
}
func safeDataPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return config.Invalid()
	}
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		current = filepath.Join(current, part)
		st, e := os.Lstat(current)
		if e != nil || st.Mode()&os.ModeSymlink != 0 {
			return config.Invalid()
		}
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if e != nil {
		return config.Invalid()
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Nlink != 1 {
		return config.Invalid()
	}
	return nil
}
func DatasetConfig(s config.Settings, bindingID, projectID, participantID string) (map[string]any, error) {
	values, e := s.Section("node", false)
	if e != nil {
		return nil, e
	}
	datasets, ok := values["dataset_bindings"].(map[string]any)
	if !ok {
		return nil, config.Invalid()
	}
	data, ok := datasets[bindingID].(map[string]any)
	if !ok {
		return nil, config.Invalid()
	}
	switch data["kind"] {
	case "npz":
		if e = config.Keys(data, []string{"kind", "host_path", "project_id", "participant_id"}, nil); e != nil {
			return nil, e
		}
	case "synthetic":
		if e = config.Keys(data, []string{"kind"}, []string{"project_id", "participant_id"}); e != nil {
			return nil, e
		}
	default:
		return nil, config.Invalid()
	}
	if v, ok := data["project_id"]; ok && v != projectID {
		return nil, config.Invalid()
	}
	if v, ok := data["participant_id"]; ok && v != participantID {
		return nil, config.Invalid()
	}
	copy := map[string]any{}
	for k, v := range data {
		copy[k] = v
	}
	return copy, nil
}
func CreateNodeAgent(ctx context.Context, s config.Settings, db *store.DB) (*executor.NodeAgent, error) {
	ec, e := s.Section("executor", true)
	if e != nil {
		return nil, e
	}
	if e = config.Keys(ec, []string{"root", "profile_path"}, nil); e != nil {
		return nil, e
	}
	node, e := s.Section("node", true)
	if e != nil {
		return nil, e
	}
	if e = config.Keys(node, []string{"node_id", "pool_id", "ledger_path", "capacity"}, []string{"service", "identity_certificate", "identity_key", "identity_ca", "dataset_bindings"}); e != nil {
		return nil, e
	}
	root, e := cfgText(ec, "root")
	if e != nil {
		return nil, e
	}
	profile, e := cfgText(ec, "profile_path")
	if e != nil {
		return nil, e
	}
	nodeID, e := cfgID(node["node_id"])
	if e != nil {
		return nil, e
	}
	poolID, e := cfgID(node["pool_id"])
	if e != nil {
		return nil, e
	}
	ledger, e := cfgText(node, "ledger_path")
	if e != nil {
		return nil, e
	}
	capacity, ok := node["capacity"].(map[string]any)
	if !ok {
		return nil, config.Invalid()
	}
	if e = config.Keys(capacity, []string{"cpu_millicores", "memory_bytes", "disk_bytes"}, []string{"pids", "io_bps"}); e != nil {
		return nil, e
	}
	cpu, e := config.GetInt(capacity, "cpu_millicores", 0, 1, 1<<50)
	if e != nil {
		return nil, e
	}
	memory, e := config.GetInt(capacity, "memory_bytes", 0, 1, 1<<50)
	if e != nil {
		return nil, e
	}
	disk, e := config.GetInt(capacity, "disk_bytes", 0, 32<<20, 1<<50)
	if e != nil {
		return nil, e
	}
	pids, e := config.GetInt(capacity, "pids", 128, 1, 128)
	if e != nil {
		return nil, e
	}
	ioBPS, e := config.GetInt(capacity, "io_bps", 16<<20, 1, 16<<20)
	if e != nil {
		return nil, e
	}
	authorizer := func(ctx context.Context, bindingID string, id executor.ExecutionIdentity, participantID string) (executor.DatasetBinding, error) {
		denied := executor.DatasetBinding{}
		if db == nil {
			return denied, config.Invalid()
		}
		var project string
		err := db.WithTx(ctx, false, func(tx *store.Tx) error {
			job, e := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id = ?", id.JobID)
			if e != nil {
				return e
			}
			attempt, e := tx.One(ctx, "SELECT * FROM jm_attempts WHERE id = ?", id.AttemptID)
			if e != nil {
				return e
			}
			binding, e := tx.One(ctx, "SELECT * FROM jm_participant_bindings WHERE id = ?", bindingID)
			if e != nil {
				return e
			}
			if job == nil || attempt == nil || binding == nil || attempt["job_id"] != id.JobID || intValue(attempt["epoch"]) != id.Epoch || intValue(job["epoch"]) != id.Epoch || intValue(attempt["number"]) != intValue(job["current_attempt"]) || !boolValue(binding["enabled"]) || binding["project_id"] != job["project_id"] || binding["participant_id"] != participantID {
				return config.Invalid()
			}
			if owner := strValue(binding["node_id"]); owner != "" && owner != nodeID {
				return config.Invalid()
			}
			raw, e := domain.CanonicalJSON(job["spec_json"])
			if e != nil {
				return e
			}
			spec, e := domain.DecodeJobSpec(raw)
			if e != nil {
				return e
			}
			matched := false
			for _, p := range spec.Participants {
				if p.ParticipantID == participantID && p.DatasetBinding == bindingID && p.Mode == "managed" && p.ComponentID != nil && *p.ComponentID == id.ComponentID {
					for _, c := range spec.Components {
						if c.ComponentID == id.ComponentID && c.Role == "participant" && c.ParticipantID != nil && *c.ParticipantID == participantID {
							matched = true
						}
					}
				}
			}
			if !matched {
				return config.Invalid()
			}
			project = spec.ProjectID
			return nil
		})
		if err != nil {
			return denied, err
		}
		data, e := DatasetConfig(s, bindingID, project, participantID)
		if e != nil {
			return denied, e
		}
		if data["kind"] == "synthetic" {
			return executor.DatasetBinding{ParticipantID: participantID, JobIDs: []string{id.JobID}, Synthetic: true}, nil
		}
		path := strValue(data["host_path"])
		if e = safeDataPath(path); e != nil {
			return denied, e
		}
		return executor.DatasetBinding{ParticipantID: participantID, JobIDs: []string{id.JobID}, Path: path}, nil
	}
	linux, e := executor.NewLinuxExecutor(profile, root, executor.WithDatasetAuthorizer(authorizer))
	if e != nil {
		return nil, e
	}
	return executor.NewNodeAgent(linux, ledger, nodeID, poolID, executor.ResourceLimits{CPUMillis: cpu, MemoryBytes: memory, DiskBytes: disk, PIDs: pids, IOBPS: ioBPS})
}
