package provision

import (
	"fmt"
	"math"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/artifacts"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

var shaPattern = regexp.MustCompile("^[a-f0-9]{64}$")
var wheelPattern = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9_.+\\-]{0,240}\\.whl$")

func newCollector(root string, maxBytes int64) (*artifacts.SafeCollector, error) {
	return artifacts.NewCollector(root, artifacts.CollectorOptions{MaxFiles: 100000, MaxFileBytes: maxBytes, MaxTotalBytes: maxBytes, MaxDepth: 64})
}
func validRelative(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return false
	}
	for _, p := range strings.Split(name, "/") {
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	return true
}
func validAbsolute(name string) bool {
	if !strings.HasPrefix(name, "/") {
		return false
	}
	for _, p := range strings.Split(name, "/") {
		if p == "." || p == ".." {
			return false
		}
	}
	return true
}
func floating(value any) (float64, error) {
	switch v := value.(type) {
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, fmt.Errorf("finite number required")
		}
		return v, nil
	case int64:
		return float64(v), nil
	case int:
		return float64(v), nil
	case interface{ Float64() (float64, error) }:
		n, e := v.Float64()
		if e == nil && (math.IsNaN(n) || math.IsInf(n, 0)) {
			e = fmt.Errorf("finite number required")
		}
		return n, e
	}
	return 0, fmt.Errorf("number required")
}
func array(value any) ([]any, bool) {
	switch v := value.(type) {
	case []any:
		return v, true
	case []string:
		r := make([]any, len(v))
		for i, x := range v {
			r[i] = x
		}
		return r, true
	case []map[string]any:
		r := make([]any, len(v))
		for i, x := range v {
			r[i] = x
		}
		return r, true
	}
	return nil, false
}
func NormalizeRuntimeConfig(configuration map[string]any) (map[string]any, error) {
	b, e := domain.CanonicalJSON(configuration)
	if e != nil {
		return nil, e
	}
	if len(b) > 2*1024*1024 {
		return nil, refused("worker_configuration_too_large")
	}
	cfg, e := decodeMap(b)
	if e != nil {
		return nil, e
	}
	allowed := map[string]bool{}
	for _, name := range []string{"schema_version", "role", "job_id", "attempt_id", "component_id", "space_id", "epoch", "spec", "spec_digest", "source_dir", "state_dir", "exchange_endpoint", "proxy_socket", "participant_id", "poll_interval", "max_backoff", "source_manifest", "dataset_bindings", "participant_principals", "reconciliation", "secret_options_file", "secret_option_names", "deadline_at", "build_dir", "built_artifacts"} {
		allowed[name] = true
	}
	for key := range cfg {
		if !allowed[key] {
			return nil, refused("unknown_runtime_configuration_field")
		}
	}
	defaults := map[string]any{"schema_version": int64(1), "source_dir": "/job/source", "state_dir": "/job/state", "exchange_endpoint": "http://proxy", "proxy_socket": "/run/hf2l/proxy.sock", "participant_id": nil, "poll_interval": 2.0, "max_backoff": 30.0, "source_manifest": map[string]any{}, "dataset_bindings": map[string]any{}, "participant_principals": map[string]any{}, "reconciliation": []any{}, "secret_options_file": nil, "secret_option_names": []any{}, "deadline_at": nil, "build_dir": "/job/build", "built_artifacts": map[string]any{}}
	for k, v := range defaults {
		if _, ok := cfg[k]; !ok {
			cfg[k] = v
		}
	}
	version, e := strictInteger(cfg["schema_version"])
	if e != nil || version != 1 {
		return nil, refused("invalid_runtime_schema")
	}
	role := str(cfg["role"])
	if role != "owner" && role != "init" && role != "client" {
		return nil, refused("invalid_runtime_role")
	}
	for _, name := range []string{"job_id", "attempt_id", "component_id", "space_id"} {
		if e = domain.ValidateIdentifier(str(cfg[name])); e != nil {
			return nil, e
		}
	}
	if cfg["participant_id"] != nil {
		if e = domain.ValidateIdentifier(str(cfg["participant_id"])); e != nil {
			return nil, e
		}
	}
	epoch, e := strictInteger(cfg["epoch"])
	if e != nil || epoch < 1 {
		return nil, refused("invalid_runtime_epoch")
	}
	specBytes, e := domain.CanonicalJSON(cfg["spec"])
	if e != nil {
		return nil, e
	}
	spec, e := domain.DecodeJobSpec(specBytes)
	if e != nil {
		return nil, e
	}
	if cfg["spec_digest"] != mustDigest(spec) {
		return nil, refused("runtime_specification_mismatch")
	}
	cfg["spec"] = spec.Map()
	for _, name := range []string{"source_dir", "state_dir", "proxy_socket"} {
		value := str(cfg[name])
		if !validAbsolute(value) {
			return nil, refused("invalid_runtime_path")
		}
		cfg[name] = strings.TrimRight(value, "/")
	}
	source, state := path.Clean(str(cfg["source_dir"])), path.Clean(str(cfg["state_dir"]))
	if source == state || strings.HasPrefix(source, state+"/") || strings.HasPrefix(state, source+"/") {
		return nil, refused("runtime_source_state_overlap")
	}
	parsed, e := url.Parse(str(cfg["exchange_endpoint"]))
	if e != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, refused("invalid_runtime_proxy")
	}
	cfg["exchange_endpoint"] = strings.TrimRight(str(cfg["exchange_endpoint"]), "/")
	poll, e := floating(cfg["poll_interval"])
	if e != nil || poll <= 0 || poll > 300 {
		return nil, refused("invalid_runtime_poll_interval")
	}
	backoff, e := floating(cfg["max_backoff"])
	if e != nil || backoff <= 0 || backoff > 300 || backoff < poll {
		return nil, refused("invalid_runtime_backoff")
	}
	cfg["poll_interval"], cfg["max_backoff"] = poll, backoff
	if cfg["deadline_at"] != nil {
		n, e := floating(cfg["deadline_at"])
		if e != nil || n <= 0 {
			return nil, refused("invalid_runtime_deadline")
		}
		cfg["deadline_at"] = n
	}
	manifest, ok := cfg["source_manifest"].(map[string]any)
	if !ok {
		return nil, refused("invalid_source_manifest")
	}
	for name, digest := range manifest {
		if !validRelative(name) || !shaPattern.MatchString(str(digest)) {
			return nil, refused("invalid_source_manifest")
		}
	}
	datasets, ok := cfg["dataset_bindings"].(map[string]any)
	if !ok {
		return nil, refused("invalid_dataset_bindings")
	}
	for name, value := range datasets {
		if e = domain.ValidateIdentifier(name); e != nil {
			return nil, e
		}
		binding, ok := value.(map[string]any)
		if !ok {
			return nil, refused("invalid_dataset_binding")
		}
		for k := range binding {
			if k != "kind" && k != "path" {
				return nil, refused("unknown_dataset_binding_field")
			}
		}
		kind := str(binding["kind"])
		if kind == "synthetic" {
			if binding["path"] != nil {
				return nil, refused("synthetic_dataset_path_forbidden")
			}
			binding["path"] = nil
		} else if kind == "npz" {
			p := str(binding["path"])
			if !strings.HasPrefix(p, "/job/data/") || !validAbsolute(p) {
				return nil, refused("dataset_outside_assigned_volume")
			}
		} else {
			return nil, refused("invalid_dataset_kind")
		}
	}
	principals, ok := cfg["participant_principals"].(map[string]any)
	if !ok {
		return nil, refused("invalid_participant_principals")
	}
	var component *domain.ComponentSpec
	for i := range spec.Components {
		if spec.Components[i].ComponentID == cfg["component_id"] {
			component = &spec.Components[i]
			break
		}
	}
	if role == "owner" || role == "init" {
		if component == nil || component.Role != "owner" || cfg["participant_id"] != nil {
			return nil, refused("runtime_owner_binding_mismatch")
		}
		if len(spec.Participants) > 0 {
			if len(principals) != len(spec.Participants) {
				return nil, refused("runtime_participant_set_mismatch")
			}
			unique := map[string]bool{}
			for _, participant := range spec.Participants {
				principal := str(principals[participant.ParticipantID])
				if e = domain.ValidateIdentifier(principal); e != nil {
					return nil, e
				}
				if unique[principal] {
					return nil, refused("duplicate_participant_principal")
				}
				unique[principal] = true
			}
		}
	} else {
		var participant *domain.ParticipantSpec
		for i := range spec.Participants {
			if spec.Participants[i].ParticipantID == cfg["participant_id"] {
				participant = &spec.Participants[i]
				break
			}
		}
		if participant == nil {
			return nil, refused("unassigned_runtime_participant")
		}
		if participant.Mode == "managed" {
			if component == nil || component.Role != "participant" || component.ParticipantID == nil || *component.ParticipantID != participant.ParticipantID {
				return nil, refused("runtime_participant_binding_mismatch")
			}
		} else if component != nil {
			return nil, refused("external_participant_component_impersonation")
		}
		if _, ok := datasets[participant.DatasetBinding]; !ok {
			return nil, refused("runtime_dataset_unapproved")
		}
	}
	names, ok := array(cfg["secret_option_names"])
	if !ok {
		return nil, refused("invalid_secret_option_names")
	}
	uniqueNames := map[string]bool{}
	for _, name := range names {
		s, ok := name.(string)
		if !ok || uniqueNames[s] {
			return nil, refused("invalid_secret_option_names")
		}
		if _, ok := spec.SecretRefs[s]; !ok {
			return nil, refused("unapproved_secret_option")
		}
		uniqueNames[s] = true
	}
	secretFile := str(cfg["secret_options_file"])
	if secretFile != "" && secretFile != "/run/hf2l/secrets.json" {
		return nil, refused("invalid_runtime_secret_path")
	}
	if (len(names) > 0) != (secretFile != "") {
		return nil, refused("runtime_secret_manifest_mismatch")
	}
	directives, ok := array(cfg["reconciliation"])
	if !ok {
		return nil, refused("invalid_reconciliation_directives")
	}
	roles := map[string]bool{}
	for _, entry := range directives {
		directive, ok := entry.(map[string]any)
		if !ok {
			return nil, refused("invalid_reconciliation_directive")
		}
		allowed := map[string]bool{}
		for _, k := range []string{"role", "action", "intent_sha256", "old_attempt_id", "old_epoch", "revocation_operation_id", "termination_operation_id", "grants_revoked", "termination_confirmed", "record_id", "acquisition_id"} {
			allowed[k] = true
		}
		for k := range directive {
			if !allowed[k] {
				return nil, refused("unknown_reconciliation_field")
			}
		}
		r := str(directive["role"])
		if (role == "client" && r != "client") || (role != "client" && r != "owner" && r != "init") || roles[r] {
			return nil, refused("invalid_reconciliation_role")
		}
		roles[r] = true
		action := str(directive["action"])
		if action != "confirmed" && action != "absent" {
			return nil, refused("invalid_reconciliation_action")
		}
		if !shaPattern.MatchString(str(directive["intent_sha256"])) || !truth(directive["grants_revoked"]) || !truth(directive["termination_confirmed"]) {
			return nil, refused("unfenced_reconciliation")
		}
		old, e := strictInteger(directive["old_epoch"])
		if e != nil || old < 1 || old >= epoch || directive["old_attempt_id"] == cfg["attempt_id"] {
			return nil, refused("invalid_reconciliation_attempt")
		}
		for _, name := range []string{"old_attempt_id", "revocation_operation_id", "termination_operation_id"} {
			if e = domain.ValidateIdentifier(str(directive[name])); e != nil {
				return nil, e
			}
		}
		for _, name := range []string{"record_id", "acquisition_id"} {
			if _, ok := directive[name]; !ok {
				directive[name] = nil
			}
			if directive[name] != nil {
				if e = domain.ValidateIdentifier(str(directive[name])); e != nil {
					return nil, e
				}
			}
		}
		if action == "confirmed" && directive["record_id"] == nil {
			return nil, refused("confirmed_publication_without_record")
		}
	}
	built, ok := cfg["built_artifacts"].(map[string]any)
	if !ok || len(built) > 256 {
		return nil, refused("invalid_built_artifacts")
	}
	if cfg["build_dir"] != "/job/build" {
		return nil, refused("invalid_runtime_build_directory")
	}
	for name, value := range built {
		if !wheelPattern.MatchString(name) {
			return nil, refused("invalid_wheel_name")
		}
		item, ok := value.(map[string]any)
		if !ok || len(item) != 2 || !shaPattern.MatchString(str(item["sha256"])) {
			return nil, refused("invalid_wheel_descriptor")
		}
		size, e := strictInteger(item["size_bytes"])
		if e != nil || size < 1 || size > 1<<40 {
			return nil, refused("invalid_wheel_size")
		}
	}
	return cfg, nil
}
func ValidateRuntimeConfig(configuration map[string]any) error {
	_, e := NormalizeRuntimeConfig(configuration)
	return e
}

// RuntimeDurableBinding matches the application adapter's attempt-independent
// source binding; attempts/epochs can rotate only after confirmed fencing.
func RuntimeDurableBinding(configuration map[string]any) (map[string]any, error) {
	cfg, e := NormalizeRuntimeConfig(configuration)
	if e != nil {
		return nil, e
	}
	spec, e := JobSpec(map[string]any{"spec": cfg["spec"], "spec_hash": cfg["spec_digest"]})
	if e != nil {
		return nil, e
	}
	role := str(cfg["role"])
	if role == "init" {
		role = "owner"
	}
	binding := map[string]any{"job_id": cfg["job_id"], "component_id": cfg["component_id"], "space_id": cfg["space_id"], "spec_digest": cfg["spec_digest"], "source_commit": spec.SourceCommit, "source_manifest": cfg["source_manifest"], "role": role, "participant_id": cfg["participant_id"], "participant_principals": cfg["participant_principals"], "dataset_bindings": cfg["dataset_bindings"]}
	if built := obj(cfg["built_artifacts"]); len(built) > 0 {
		binding["built_artifacts"] = built
	}
	return binding, nil
}
func RuntimeSourceIdentity(configuration map[string]any) (string, error) {
	binding, e := RuntimeDurableBinding(configuration)
	if e != nil {
		return "", e
	}
	digest, e := digestMap(binding)
	if e != nil {
		return "", e
	}
	return "hf2l-managed-source-v1:sha256:" + digest, nil
}
