package domain

import (
	"encoding/json"
	"math"
	"math/big"
	"regexp"
	"strings"
	"unicode/utf8"
)

type ResourceRequest struct {
	PoolID         string  `json:"pool_id"`
	CPUMillicores  int64   `json:"cpu_millicores"`
	MemoryBytes    int64   `json:"memory_bytes"`
	DiskBytes      int64   `json:"disk_bytes"`
	GPUCount       int64   `json:"gpu_count"`
	GPUProfile     *string `json:"gpu_profile"`
	SandboxProfile string  `json:"sandbox_profile"`
}
type ComponentSpec struct {
	ComponentID   string          `json:"component_id"`
	Role          string          `json:"role"`
	Resources     ResourceRequest `json:"resources"`
	ParticipantID *string         `json:"participant_id"`
}
type ParticipantSpec struct {
	ParticipantID  string  `json:"participant_id"`
	DatasetBinding string  `json:"dataset_binding"`
	Mode           string  `json:"mode"`
	ComponentID    *string `json:"component_id"`
}
type JobSpec struct {
	ProjectID          string            `json:"project_id"`
	Name               string            `json:"name"`
	SourceID           string            `json:"source_id"`
	SourceCommit       string            `json:"source_commit"`
	RuntimeImage       string            `json:"runtime_image"`
	Plugin             string            `json:"plugin"`
	Options            map[string]any    `json:"options"`
	SecretRefs         map[string]string `json:"secret_refs"`
	Participants       []ParticipantSpec `json:"participants"`
	Components         []ComponentSpec   `json:"components"`
	TargetRound        int64             `json:"target_round"`
	MaxDurationSeconds int64             `json:"max_duration_seconds"`
}
type ArtifactLocator struct {
	Kind         string  `json:"kind"`
	SpaceID      *string `json:"space_id,omitempty"`
	RecordID     *string `json:"record_id,omitempty"`
	AttachmentID *string `json:"attachment_id,omitempty"`
	ResourceID   *string `json:"resource_id,omitempty"`
	RelativePath *string `json:"relative_path,omitempty"`
}

var (
	commitPattern    = regexp.MustCompile(`^(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$`)
	digestPattern    = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	pluginPattern    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?::[A-Za-z_][A-Za-z0-9_]*)?$`)
	camelBoundary    = regexp.MustCompile(`([a-z])([A-Z])`)
	optionSeparators = regexp.MustCompile(`[^a-z0-9]+`)
	secretOption     = regexp.MustCompile(`(^|_)(password|passwd|secret|token|credentials|private_key|access_key|api_key)($|_)`)
)

func badSpec() error { return Err(422, "invalid_job_spec") }
func stringPointerValue(v *string) any {
	if v == nil {
		return nil
	}
	return *v
}
func (r ResourceRequest) Map() map[string]any {
	return map[string]any{"pool_id": r.PoolID, "cpu_millicores": r.CPUMillicores, "memory_bytes": r.MemoryBytes, "disk_bytes": r.DiskBytes, "gpu_count": r.GPUCount, "gpu_profile": stringPointerValue(r.GPUProfile), "sandbox_profile": r.SandboxProfile}
}
func (c ComponentSpec) Map() map[string]any {
	return map[string]any{"component_id": c.ComponentID, "role": c.Role, "resources": c.Resources.Map(), "participant_id": stringPointerValue(c.ParticipantID)}
}
func (p ParticipantSpec) Map() map[string]any {
	return map[string]any{"participant_id": p.ParticipantID, "dataset_binding": p.DatasetBinding, "mode": p.Mode, "component_id": stringPointerValue(p.ComponentID)}
}
func (s JobSpec) Map() map[string]any {
	components := make([]any, len(s.Components))
	for i, c := range s.Components {
		components[i] = c.Map()
	}
	participants := make([]any, len(s.Participants))
	for i, p := range s.Participants {
		participants[i] = p.Map()
	}
	secrets := make(map[string]any, len(s.SecretRefs))
	for k, v := range s.SecretRefs {
		secrets[k] = v
	}
	return map[string]any{"project_id": s.ProjectID, "name": s.Name, "source_id": s.SourceID, "source_commit": strings.ToLower(s.SourceCommit), "runtime_image": s.RuntimeImage, "plugin": s.Plugin, "options": CloneMap(s.Options), "secret_refs": secrets, "participants": participants, "components": components, "target_round": s.TargetRound, "max_duration_seconds": s.MaxDurationSeconds}
}
func (s JobSpec) Digest() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	return SpecHash(s.Map())
}
func (s JobSpec) MarshalJSON() ([]byte, error) { return CanonicalJSON(s.Map()) }
func (s *JobSpec) UnmarshalJSON(raw []byte) error {
	value, err := DecodeJobSpec(raw)
	if err == nil {
		*s = value
	}
	return err
}
func object(raw []byte, allowed ...string) (map[string]any, error) {
	value, err := DecodeJSON(raw)
	if err != nil {
		return nil, badSpec()
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, badSpec()
	}
	accepted := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		accepted[name] = true
	}
	for name := range m {
		if !accepted[name] {
			return nil, badSpec()
		}
	}
	return m, nil
}
func requireString(m map[string]any, name string) (string, error) {
	value, ok := m[name]
	if !ok {
		return "", badSpec()
	}
	s, ok := value.(string)
	if !ok {
		return "", badSpec()
	}
	return s, nil
}
func optionalString(m map[string]any, name string) (*string, error) {
	value, ok := m[name]
	if !ok || value == nil {
		return nil, nil
	}
	s, ok := value.(string)
	if !ok {
		return nil, badSpec()
	}
	return &s, nil
}
func strictInt(value any) (int64, bool) {
	switch v := value.(type) {
	case json.Number:
		if !jsonNumberPattern.MatchString(string(v)) || strings.ContainsAny(string(v), ".eE") {
			return 0, false
		}
		n, ok := new(big.Int).SetString(string(v), 10)
		if !ok || !n.IsInt64() {
			return 0, false
		}
		return n.Int64(), true
	case int:
		return int64(v), true
	case int8:
		return int64(v), true
	case int16:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	case uint:
		if uint64(v) > math.MaxInt64 {
			return 0, false
		}
		return int64(v), true
	case uint8:
		return int64(v), true
	case uint16:
		return int64(v), true
	case uint32:
		return int64(v), true
	case uint64:
		if v > math.MaxInt64 {
			return 0, false
		}
		return int64(v), true
	}
	return 0, false
}
func requireInt(m map[string]any, name string) (int64, error) {
	v, ok := m[name]
	if !ok {
		return 0, badSpec()
	}
	n, ok := strictInt(v)
	if !ok {
		return 0, badSpec()
	}
	return n, nil
}
func nestedRaw(value any) ([]byte, error) { return CanonicalJSON(value) }
func DecodeJobSpec(raw []byte) (JobSpec, error) {
	var s JobSpec
	m, err := object(raw, "project_id", "name", "source_id", "source_commit", "runtime_image", "plugin", "options", "secret_refs", "participants", "components", "target_round", "max_duration_seconds")
	if err != nil {
		return s, badSpec()
	}
	for name, target := range map[string]*string{"project_id": &s.ProjectID, "name": &s.Name, "source_id": &s.SourceID, "source_commit": &s.SourceCommit, "runtime_image": &s.RuntimeImage, "plugin": &s.Plugin} {
		*target, err = requireString(m, name)
		if err != nil {
			return s, badSpec()
		}
	}
	s.SourceCommit = strings.ToLower(s.SourceCommit)
	s.TargetRound, err = requireInt(m, "target_round")
	if err != nil {
		return s, badSpec()
	}
	s.MaxDurationSeconds, err = requireInt(m, "max_duration_seconds")
	if err != nil {
		return s, badSpec()
	}
	s.Options = map[string]any{}
	if v, ok := m["options"]; ok {
		var valid bool
		s.Options, valid = v.(map[string]any)
		if !valid {
			return s, badSpec()
		}
		s.Options = CloneMap(s.Options)
	}
	s.SecretRefs = map[string]string{}
	if v, ok := m["secret_refs"]; ok {
		secrets, valid := v.(map[string]any)
		if !valid {
			return s, badSpec()
		}
		for k, v := range secrets {
			str, valid := v.(string)
			if !valid {
				return s, badSpec()
			}
			s.SecretRefs[k] = str
		}
	}
	s.Participants = []ParticipantSpec{}
	if v, ok := m["participants"]; ok {
		list, valid := v.([]any)
		if !valid {
			return s, badSpec()
		}
		if len(list) > 10000 {
			return s, badSpec()
		}
		for _, item := range list {
			raw, err := nestedRaw(item)
			if err != nil {
				return s, badSpec()
			}
			var p ParticipantSpec
			if err := p.UnmarshalJSON(raw); err != nil {
				return s, badSpec()
			}
			s.Participants = append(s.Participants, p)
		}
	}
	values, ok := m["components"].([]any)
	if !ok || len(values) < 1 || len(values) > 1024 {
		return s, badSpec()
	}
	for _, item := range values {
		raw, err := nestedRaw(item)
		if err != nil {
			return s, badSpec()
		}
		var c ComponentSpec
		if err := c.UnmarshalJSON(raw); err != nil {
			return s, badSpec()
		}
		s.Components = append(s.Components, c)
	}
	if err := s.Validate(); err != nil {
		return JobSpec{}, err
	}
	return s, nil
}
func JobSpecFromMap(value map[string]any) (JobSpec, error) {
	raw, err := CanonicalJSON(value)
	if err != nil {
		return JobSpec{}, badSpec()
	}
	return DecodeJobSpec(raw)
}
func (r *ResourceRequest) UnmarshalJSON(raw []byte) error {
	m, err := object(raw, "pool_id", "cpu_millicores", "memory_bytes", "disk_bytes", "gpu_count", "gpu_profile", "sandbox_profile")
	if err != nil {
		return err
	}
	out := ResourceRequest{SandboxProfile: "runsc-cpu-v1"}
	out.PoolID, err = requireString(m, "pool_id")
	if err != nil {
		return err
	}
	for name, target := range map[string]*int64{"cpu_millicores": &out.CPUMillicores, "memory_bytes": &out.MemoryBytes, "disk_bytes": &out.DiskBytes} {
		*target, err = requireInt(m, name)
		if err != nil {
			return err
		}
	}
	if _, ok := m["gpu_count"]; ok {
		out.GPUCount, err = requireInt(m, "gpu_count")
		if err != nil {
			return err
		}
	}
	out.GPUProfile, err = optionalString(m, "gpu_profile")
	if err != nil {
		return err
	}
	if _, ok := m["sandbox_profile"]; ok {
		out.SandboxProfile, err = requireString(m, "sandbox_profile")
		if err != nil {
			return err
		}
	}
	if err := out.Validate(); err != nil {
		return err
	}
	*r = out
	return nil
}
func (c *ComponentSpec) UnmarshalJSON(raw []byte) error {
	m, err := object(raw, "component_id", "role", "resources", "participant_id")
	if err != nil {
		return err
	}
	var out ComponentSpec
	out.ComponentID, err = requireString(m, "component_id")
	if err != nil {
		return err
	}
	out.Role, err = requireString(m, "role")
	if err != nil {
		return err
	}
	out.ParticipantID, err = optionalString(m, "participant_id")
	if err != nil {
		return err
	}
	value, ok := m["resources"]
	if !ok {
		return badSpec()
	}
	child, err := nestedRaw(value)
	if err != nil {
		return badSpec()
	}
	if err := out.Resources.UnmarshalJSON(child); err != nil {
		return err
	}
	if err := out.Validate(); err != nil {
		return err
	}
	*c = out
	return nil
}
func (p *ParticipantSpec) UnmarshalJSON(raw []byte) error {
	m, err := object(raw, "participant_id", "dataset_binding", "mode", "component_id")
	if err != nil {
		return err
	}
	out := ParticipantSpec{Mode: "external"}
	out.ParticipantID, err = requireString(m, "participant_id")
	if err != nil {
		return err
	}
	out.DatasetBinding, err = requireString(m, "dataset_binding")
	if err != nil {
		return err
	}
	out.ComponentID, err = optionalString(m, "component_id")
	if err != nil {
		return err
	}
	if _, ok := m["mode"]; ok {
		out.Mode, err = requireString(m, "mode")
		if err != nil {
			return err
		}
	}
	if err := out.Validate(); err != nil {
		return err
	}
	*p = out
	return nil
}
func (r ResourceRequest) Validate() error {
	if !ValidIdentifier(r.PoolID) || !ValidIdentifier(r.SandboxProfile) || r.CPUMillicores < 1 || r.CPUMillicores > 1000000 || r.MemoryBytes < 1 || r.MemoryBytes > 1<<50 || r.DiskBytes < 1 || r.DiskBytes > 1<<50 || r.GPUCount < 0 || r.GPUCount > 1024 {
		return badSpec()
	}
	if r.GPUProfile != nil && !ValidIdentifier(*r.GPUProfile) {
		return badSpec()
	}
	if (r.GPUCount != 0) != (r.GPUProfile != nil) {
		return badSpec()
	}
	return nil
}
func (c ComponentSpec) Validate() error {
	if !ValidIdentifier(c.ComponentID) || (c.Role != "owner" && c.Role != "participant" && c.Role != "build") {
		return badSpec()
	}
	if c.ParticipantID != nil && !ValidIdentifier(*c.ParticipantID) {
		return badSpec()
	}
	if (c.Role == "participant") != (c.ParticipantID != nil) {
		return badSpec()
	}
	return c.Resources.Validate()
}
func (p ParticipantSpec) Validate() error {
	if !ValidIdentifier(p.ParticipantID) || !ValidIdentifier(p.DatasetBinding) || (p.Mode != "external" && p.Mode != "managed") {
		return badSpec()
	}
	if p.ComponentID != nil && !ValidIdentifier(*p.ComponentID) {
		return badSpec()
	}
	if (p.Mode == "managed") != (p.ComponentID != nil) {
		return badSpec()
	}
	return nil
}
func (s JobSpec) Validate() error {
	if !ValidIdentifier(s.ProjectID) || !ValidIdentifier(s.SourceID) || !commitPattern.MatchString(s.SourceCommit) || (!digestPattern.MatchString(s.RuntimeImage) && !ValidIdentifier(s.RuntimeImage)) {
		return badSpec()
	}
	if utf8.RuneCountInString(s.Name) < 1 || utf8.RuneCountInString(s.Name) > 200 || strings.TrimSpace(s.Name) == "" || !utf8.ValidString(s.Name) {
		return badSpec()
	}
	for _, r := range s.Name {
		if r < 32 || r == 127 {
			return badSpec()
		}
	}
	if len(s.Plugin) > 256 || !pluginPattern.MatchString(s.Plugin) || s.TargetRound < 1 || s.TargetRound > 1000000 || s.MaxDurationSeconds < 1 || s.MaxDurationSeconds > 2592000 {
		return badSpec()
	}
	if len(s.Components) < 1 || len(s.Components) > 1024 || len(s.Participants) > 10000 {
		return badSpec()
	}
	if err := validateOption(s.Options, 0); err != nil {
		return err
	}
	raw, err := CanonicalJSON(CloneMap(s.Options))
	if err != nil || len(raw) > 65536 {
		return badSpec()
	}
	if len(s.SecretRefs) > 64 {
		return badSpec()
	}
	for k, v := range s.SecretRefs {
		if !ValidIdentifier(k) || !ValidIdentifier(v) {
			return badSpec()
		}
	}
	components := map[string]ComponentSpec{}
	participants := map[string]ParticipantSpec{}
	owners := 0
	for _, c := range s.Components {
		if err := c.Validate(); err != nil {
			return err
		}
		if _, ok := components[c.ComponentID]; ok {
			return badSpec()
		}
		components[c.ComponentID] = c
		if c.Role == "owner" {
			owners++
		}
	}
	if owners != 1 {
		return badSpec()
	}
	for _, p := range s.Participants {
		if err := p.Validate(); err != nil {
			return err
		}
		if _, ok := participants[p.ParticipantID]; ok {
			return badSpec()
		}
		participants[p.ParticipantID] = p
		if p.Mode == "external" {
			if _, ok := components[ExternalComponentID(p.ParticipantID)]; ok {
				return badSpec()
			}
		}
	}
	for _, p := range s.Participants {
		if p.Mode == "managed" {
			c, ok := components[*p.ComponentID]
			if !ok || c.Role != "participant" || c.ParticipantID == nil || *c.ParticipantID != p.ParticipantID {
				return badSpec()
			}
		}
	}
	for _, c := range s.Components {
		if c.Role == "participant" {
			p, ok := participants[*c.ParticipantID]
			if !ok || p.Mode != "managed" || p.ComponentID == nil || *p.ComponentID != c.ComponentID {
				return badSpec()
			}
		}
	}
	if value, ok := s.Options["minimum_participants"]; ok {
		n, ok := strictInt(value)
		if !ok || n < 2 || n > int64(len(s.Participants)) {
			return badSpec()
		}
	}
	return nil
}
func forbiddenOption(key string) bool {
	normal := strings.Trim(optionSeparators.ReplaceAllString(strings.ToLower(camelBoundary.ReplaceAllString(key, "${1}_${2}")), "_"), "_")
	switch normal {
	case "command", "commands", "cmd", "mount", "mounts", "host_path", "docker_flags", "executor_flags", "runtime_flags", "privileged", "network_mode":
		return true
	}
	if secretOption.MatchString(normal) {
		return true
	}
	switch strings.ReplaceAll(normal, "_", "") {
	case "apikey", "accesskey", "privatekey", "authorization", "bearertoken", "accesstoken", "refreshtoken":
		return true
	}
	return false
}
func validateOption(value any, depth int) error {
	if depth > 8 {
		return badSpec()
	}
	switch v := value.(type) {
	case nil, bool:
		return nil
	case string:
		if !utf8.ValidString(v) || utf8.RuneCountInString(v) > 8192 {
			return badSpec()
		}
		return nil
	case map[string]any:
		for k, item := range v {
			if k == "" || !utf8.ValidString(k) || utf8.RuneCountInString(k) > 128 || forbiddenOption(k) {
				return badSpec()
			}
			if err := validateOption(item, depth+1); err != nil {
				return err
			}
		}
		return nil
	case []any:
		for _, item := range v {
			if err := validateOption(item, depth+1); err != nil {
				return err
			}
		}
		return nil
	case json.Number:
		if !jsonNumberPattern.MatchString(string(v)) {
			return badSpec()
		}
		if strings.ContainsAny(string(v), ".eE") {
			f, err := v.Float64()
			if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
				return badSpec()
			}
		}
		return nil
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return nil
	case float32:
		if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) {
			return badSpec()
		}
		return nil
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return badSpec()
		}
		return nil
	}
	return badSpec()
}
func ExternalComponentID(participant string) string {
	hash, err := SpecHash([]string{participant})
	if err != nil {
		return ""
	}
	return "participant-" + hash[:40]
}
func DecodeArtifactLocator(raw []byte) (ArtifactLocator, error) {
	m, err := object(raw, "kind", "space_id", "record_id", "attachment_id", "resource_id", "relative_path")
	if err != nil {
		return ArtifactLocator{}, Err(422, "invalid_artifact_locator")
	}
	var l ArtifactLocator
	l.Kind, err = requireString(m, "kind")
	if err != nil {
		return l, Err(422, "invalid_artifact_locator")
	}
	for name, target := range map[string]**string{"space_id": &l.SpaceID, "record_id": &l.RecordID, "attachment_id": &l.AttachmentID, "resource_id": &l.ResourceID, "relative_path": &l.RelativePath} {
		*target, err = optionalString(m, name)
		if err != nil {
			return l, Err(422, "invalid_artifact_locator")
		}
	}
	if err := l.Validate(); err != nil {
		return ArtifactLocator{}, err
	}
	return l, nil
}
func LocatorFromMap(value map[string]any) (ArtifactLocator, error) {
	raw, err := CanonicalJSON(value)
	if err != nil {
		return ArtifactLocator{}, Err(422, "invalid_artifact_locator")
	}
	return DecodeArtifactLocator(raw)
}
func (l *ArtifactLocator) UnmarshalJSON(raw []byte) error {
	value, err := DecodeArtifactLocator(raw)
	if err == nil {
		*l = value
	}
	return err
}
func (l ArtifactLocator) Validate() error {
	bad := func() error { return Err(422, "invalid_artifact_locator") }
	for _, value := range []*string{l.SpaceID, l.RecordID, l.AttachmentID, l.ResourceID} {
		if value != nil && !ValidIdentifier(*value) {
			return bad()
		}
	}
	if l.RelativePath != nil {
		s := *l.RelativePath
		if !utf8.ValidString(s) || s == "" || utf8.RuneCountInString(s) > 1024 || strings.HasPrefix(s, "/") || strings.Contains(s, "\\") {
			return bad()
		}
		for _, r := range s {
			if r < 32 {
				return bad()
			}
		}
		pieces := strings.Split(s, "/")
		if len(pieces) > 64 {
			return bad()
		}
		for _, p := range pieces {
			if p == "" || p == "." || p == ".." {
				return bad()
			}
		}
	}
	switch l.Kind {
	case "exchange":
		if l.SpaceID == nil || l.RecordID == nil || l.AttachmentID == nil || l.ResourceID != nil || l.RelativePath != nil {
			return bad()
		}
	case "local":
		if l.ResourceID == nil || l.RelativePath == nil || l.SpaceID != nil || l.RecordID != nil || l.AttachmentID != nil {
			return bad()
		}
	default:
		return bad()
	}
	return nil
}
func (l ArtifactLocator) Map() map[string]any {
	m := map[string]any{"kind": l.Kind}
	for name, value := range map[string]*string{"space_id": l.SpaceID, "record_id": l.RecordID, "attachment_id": l.AttachmentID, "resource_id": l.ResourceID, "relative_path": l.RelativePath} {
		if value != nil {
			m[name] = *value
		}
	}
	return m
}
