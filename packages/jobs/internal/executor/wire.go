package executor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

func strictDecode(data []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	d.UseNumber()
	if err := d.Decode(target); err != nil {
		return err
	}
	var more any
	if d.Decode(&more) != io.EOF {
		return fmt.Errorf("multiple JSON values")
	}
	return nil
}
func objectFields(data []byte) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil || m == nil {
		return nil, fmt.Errorf("object required")
	}
	return m, nil
}
func (i *ExecutionIdentity) UnmarshalJSON(data []byte) error {
	type alias ExecutionIdentity
	var value alias
	if err := strictDecode(data, &value); err != nil {
		return err
	}
	*i = ExecutionIdentity(value)
	return i.Validate()
}
func (r *ResourceLimits) UnmarshalJSON(data []byte) error {
	fields, err := objectFields(data)
	if err != nil {
		return err
	}
	for _, key := range []string{"cpu_millis", "memory_bytes", "disk_bytes"} {
		if v, ok := fields[key]; !ok || string(v) == "null" {
			return refused("invalid_resources")
		}
	}
	for _, v := range fields {
		if string(v) == "null" {
			return refused("invalid_resources")
		}
	}
	type alias ResourceLimits
	value := alias{PIDs: 128, IOBPS: 16 << 20}
	if err := strictDecode(data, &value); err != nil {
		return err
	}
	*r = ResourceLimits(value)
	return r.Validate()
}
func (s *ExecutionSpec) UnmarshalJSON(data []byte) error {
	fields, err := objectFields(data)
	if err != nil {
		return err
	}
	for _, key := range []string{"identity", "image_digest", "source_path", "state_path", "argv", "resources", "proxy_endpoint"} {
		if _, ok := fields[key]; !ok {
			return refused("invalid_invocation")
		}
	}
	nullable := map[string]bool{"proxy_endpoint": true, "deadline": true, "config_path": true, "secret_path": true, "dataset_binding_id": true, "participant_id": true, "build_input_path": true}
	for key, v := range fields {
		if string(v) == "null" && !nullable[key] {
			return refused("invalid_invocation")
		}
	}
	type alias ExecutionSpec
	value := alias{LeaseSeconds: 120, Profile: "runsc-cpu-v1", Role: "owner"}
	if err := strictDecode(data, &value); err != nil {
		return err
	}
	*s = ExecutionSpec(value)
	return s.Validate()
}
func (s ExecutionSpec) Map() map[string]any {
	optional := func(v string) any {
		if v == "" {
			return nil
		}
		return v
	}
	lease := any(s.LeaseSeconds)
	if math.IsNaN(s.LeaseSeconds) || math.IsInf(s.LeaseSeconds, 0) {
		lease = s.LeaseSeconds
	} else if math.Trunc(s.LeaseSeconds) == s.LeaseSeconds && math.Abs(s.LeaseSeconds) < 1<<53 {
		lease = int64(s.LeaseSeconds)
	}
	return map[string]any{
		"identity": s.Identity, "image_digest": s.ImageDigest, "source_path": s.SourcePath, "state_path": s.StatePath,
		"argv": s.Argv, "proxy_endpoint": optional(s.ProxyEndpoint), "resources": s.Resources, "lease_seconds": lease,
		"pool_id": s.PoolID, "node_id": s.NodeID, "deadline": s.Deadline, "config_path": optional(s.ConfigPath),
		"profile": s.Profile, "role": s.Role, "secret_path": optional(s.SecretPath),
		"dataset_binding_id": optional(s.DatasetBindingID), "participant_id": optional(s.ParticipantID), "build_input_path": optional(s.BuildInputPath),
	}
}
func (s ExecutionSpec) MarshalJSON() ([]byte, error) { return domain.CanonicalJSON(s.Map()) }
func (o RuntimeObservation) MarshalJSON() ([]byte, error) {
	optional := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	details := o.Details
	if details == nil {
		details = map[string]any{}
	}
	metrics := o.Metrics
	if metrics == nil {
		metrics = map[string]float64{}
	}
	publication := o.PublicationStatus
	if publication == "" {
		publication = "unknown"
	}
	return json.Marshal(map[string]any{"identity": o.Identity, "state": o.State, "termination_confirmed": o.TerminationConfirmed,
		"publication_status": publication, "current_round": o.CurrentRound, "error_code": optional(o.ErrorCode), "transient": o.Transient,
		"exit_code": o.ExitCode, "details": details, "metrics": metrics, "phase": optional(o.Phase), "readiness": optional(o.Readiness)})
}

func (d *BackingDevice) UnmarshalJSON(data []byte) error {
	fields, err := objectFields(data)
	if err != nil {
		return err
	}
	for _, k := range []string{"path", "major", "minor", "sysfs_path"} {
		if raw, ok := fields[k]; !ok || string(raw) == "null" {
			return refused("unqualified_profile")
		}
	}
	type alias BackingDevice
	var value alias
	if err = strictDecode(data, &value); err != nil {
		return err
	}
	*d = BackingDevice(value)
	if d.Major < 0 || d.Minor < 0 || d.Path == "" || d.SysfsPath == "" {
		return refused("unqualified_profile")
	}
	return nil
}
