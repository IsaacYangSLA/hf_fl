// Package build validates opaque products of the qualified sandbox build adapter.
// Trusted manager code never imports source hooks, installs wheels, or opens them as archives.
package build

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/source"
)

const MaxBuildBytes int64 = 256 << 20
const ChunkBytes = 65536

var sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var commitPattern = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)
var wheelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+!-]*\.whl$`)
var externalWheelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+\-]{0,240}\.whl$`)
var distributionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.!+_-]*$`)
var normalizeDistribution = regexp.MustCompile(`[-_.]+`)

func failure(code string) error { return domain.Err(422, code) }
func relative(path string, dot bool) bool {
	if dot && path == "." {
		return true
	}
	if path == "" || strings.HasPrefix(path, "/") || strings.Contains(path, "\\") {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	for _, c := range path {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}
func absolute(path string) bool {
	return filepath.IsAbs(path) && path != "/" && filepath.Clean(path) == path
}
func validManifest(m map[string]string) bool {
	if len(m) == 0 {
		return false
	}
	for n, h := range m {
		if !relative(n, false) || !sha256Pattern.MatchString(h) {
			return false
		}
	}
	return true
}
func dependencies(m map[string]string) (map[string]string, error) {
	result := map[string]string{}
	for n, v := range m {
		if !distributionPattern.MatchString(n) || v == "" || len(v) > 200 || !versionPattern.MatchString(v) {
			return nil, failure("invalid_build_dependencies")
		}
		normalized := strings.ToLower(normalizeDistribution.ReplaceAllString(n, "-"))
		if _, ok := result[normalized]; ok {
			return nil, failure("invalid_build_dependencies")
		}
		result[normalized] = v
	}
	if _, ok := result["build"]; !ok {
		return nil, failure("invalid_build_dependencies")
	}
	return result, nil
}

type Config struct {
	SchemaVersion        int               `json:"schema_version"`
	Role                 string            `json:"role"`
	JobID                string            `json:"job_id"`
	AttemptID            string            `json:"attempt_id"`
	ComponentID          string            `json:"component_id"`
	Epoch                int64             `json:"epoch"`
	Spec                 domain.JobSpec    `json:"spec"`
	SpecDigest           string            `json:"spec_digest"`
	SourceDir            string            `json:"source_dir"`
	StateDir             string            `json:"state_dir"`
	SourceManifest       map[string]string `json:"source_manifest"`
	ProjectSubdir        string            `json:"project_subdir"`
	ApprovedDependencies map[string]string `json:"approved_dependencies"`
}

func (c Config) Defaults() Config {
	if c.SchemaVersion == 0 {
		c.SchemaVersion = 1
	}
	if c.Role == "" {
		c.Role = "build"
	}
	if c.SourceDir == "" {
		c.SourceDir = "/job/source"
	}
	if c.StateDir == "" {
		c.StateDir = "/job/state"
	}
	if c.ProjectSubdir == "" {
		c.ProjectSubdir = "."
	}
	c.SourceManifest = source.CloneManifest(c.SourceManifest)
	if normalized, e := dependencies(c.ApprovedDependencies); e == nil {
		c.ApprovedDependencies = normalized
	}
	return c
}
func (c Config) Validate() error {
	if c.SchemaVersion != 1 || c.Role != "build" || c.Epoch < 1 || domain.ValidateIdentifier(c.JobID) != nil || domain.ValidateIdentifier(c.AttemptID) != nil || domain.ValidateIdentifier(c.ComponentID) != nil {
		return failure("invalid_build_config")
	}
	if e := c.Spec.Validate(); e != nil {
		return e
	}
	digest, e := c.Spec.Digest()
	if e != nil || digest != c.SpecDigest {
		return failure("build_spec_digest_mismatch")
	}
	found := false
	for _, component := range c.Spec.Components {
		if component.ComponentID == c.ComponentID && component.Role == "build" {
			found = true
		}
	}
	if !found {
		return failure("build_component_mismatch")
	}
	if !absolute(c.SourceDir) || !absolute(c.StateDir) || c.SourceDir == c.StateDir || strings.HasPrefix(c.SourceDir, c.StateDir+"/") || strings.HasPrefix(c.StateDir, c.SourceDir+"/") || !relative(c.ProjectSubdir, true) || !validManifest(c.SourceManifest) {
		return failure("invalid_build_config")
	}
	_, e = dependencies(c.ApprovedDependencies)
	return e
}
func (c Config) Map() map[string]any {
	return map[string]any{"schema_version": c.SchemaVersion, "role": c.Role, "job_id": c.JobID, "attempt_id": c.AttemptID, "component_id": c.ComponentID, "epoch": c.Epoch, "spec": c.Spec.Map(), "spec_digest": c.SpecDigest, "source_dir": c.SourceDir, "state_dir": c.StateDir, "source_manifest": source.CloneManifest(c.SourceManifest), "project_subdir": c.ProjectSubdir, "approved_dependencies": clone(c.ApprovedDependencies)}
}
func (c Config) DurableBinding() Binding {
	return Binding{1, c.JobID, c.ComponentID, c.SpecDigest, c.Spec.SourceCommit, source.CloneManifest(c.SourceManifest), c.ProjectSubdir, clone(c.ApprovedDependencies)}
}
func (c Config) MarshalJSON() ([]byte, error) { return domain.CanonicalJSON(c.Map()) }
func (c *Config) UnmarshalJSON(raw []byte) error {
	if e := nonNullObject(raw); e != nil {
		return e
	}
	type plain Config
	v := plain{SchemaVersion: 1, Role: "build", SourceDir: "/job/source", StateDir: "/job/state", ProjectSubdir: "."}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(&v); e != nil {
		return failure("invalid_build_config")
	}
	result := Config(v)
	normalized, e := dependencies(result.ApprovedDependencies)
	if e != nil {
		return e
	}
	result.ApprovedDependencies = normalized
	if e = result.Validate(); e != nil {
		return e
	}
	*c = result
	return nil
}
func DecodeConfig(raw []byte) (Config, error) {
	var c Config
	e := json.Unmarshal(raw, &c)
	return c, e
}
func nonNullObject(raw []byte) error {
	value, e := domain.DecodeJSON(raw)
	if e != nil {
		return failure("invalid_build_descriptor")
	}
	m, ok := value.(map[string]any)
	if !ok {
		return failure("invalid_build_descriptor")
	}
	for _, v := range m {
		if v == nil {
			return failure("invalid_build_descriptor")
		}
	}
	return nil
}
func clone(m map[string]string) map[string]string {
	result := map[string]string{}
	for k, v := range m {
		result[k] = v
	}
	return result
}

type Artifact struct {
	Filename  string `json:"filename"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

func (a Artifact) Validate() error {
	if len(a.Filename) > 255 || !wheelPattern.MatchString(a.Filename) || !sha256Pattern.MatchString(a.SHA256) || a.SizeBytes < 1 || a.SizeBytes > 1<<40 {
		return failure("invalid_build_artifact")
	}
	return nil
}
func (a *Artifact) UnmarshalJSON(raw []byte) error {
	if e := nonNullObject(raw); e != nil {
		return e
	}
	type plain Artifact
	var v plain
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(&v); e != nil {
		return failure("invalid_build_artifact")
	}
	result := Artifact(v)
	if e := result.Validate(); e != nil {
		return e
	}
	*a = result
	return nil
}

type Binding struct {
	SchemaVersion        int               `json:"schema_version"`
	JobID                string            `json:"job_id"`
	ComponentID          string            `json:"component_id"`
	SpecDigest           string            `json:"spec_digest"`
	SourceCommit         string            `json:"source_commit"`
	SourceManifest       map[string]string `json:"source_manifest"`
	ProjectSubdir        string            `json:"project_subdir"`
	ApprovedDependencies map[string]string `json:"approved_dependencies"`
}

func (b Binding) Validate() error {
	if b.SchemaVersion != 1 || domain.ValidateIdentifier(b.JobID) != nil || domain.ValidateIdentifier(b.ComponentID) != nil || !sha256Pattern.MatchString(b.SpecDigest) || !commitPattern.MatchString(b.SourceCommit) || !validManifest(b.SourceManifest) || !relative(b.ProjectSubdir, true) {
		return failure("invalid_build_binding")
	}
	_, e := dependencies(b.ApprovedDependencies)
	return e
}
func (b Binding) Map() map[string]any {
	return map[string]any{"schema_version": b.SchemaVersion, "job_id": b.JobID, "component_id": b.ComponentID, "spec_digest": b.SpecDigest, "source_commit": b.SourceCommit, "source_manifest": source.CloneManifest(b.SourceManifest), "project_subdir": b.ProjectSubdir, "approved_dependencies": clone(b.ApprovedDependencies)}
}
func (b Binding) MarshalJSON() ([]byte, error) { return domain.CanonicalJSON(b.Map()) }
func (b *Binding) UnmarshalJSON(raw []byte) error {
	if e := nonNullObject(raw); e != nil {
		return e
	}
	type plain Binding
	v := plain{SchemaVersion: 1}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(&v); e != nil {
		return failure("invalid_build_binding")
	}
	result := Binding(v)
	normalized, e := dependencies(result.ApprovedDependencies)
	if e != nil {
		return e
	}
	result.ApprovedDependencies = normalized
	if e = result.Validate(); e != nil {
		return e
	}
	*b = result
	return nil
}

type Result struct {
	SchemaVersion int      `json:"schema_version"`
	Status        string   `json:"status"`
	Binding       Binding  `json:"binding"`
	Wheel         Artifact `json:"wheel"`
}

func (r Result) ValidateBinding(c Config) error {
	if e := c.Validate(); e != nil {
		return e
	}
	if r.SchemaVersion != 1 || r.Status != "completed" {
		return failure("invalid_build_result")
	}
	if e := r.Binding.Validate(); e != nil {
		return e
	}
	if e := r.Wheel.Validate(); e != nil {
		return e
	}
	actual, e := domain.CanonicalJSON(r.Binding.Map())
	if e != nil {
		return e
	}
	expected, e := domain.CanonicalJSON(c.DurableBinding().Map())
	if e != nil {
		return e
	}
	if !bytes.Equal(actual, expected) {
		return failure("build_result_binding_mismatch")
	}
	return nil
}
func DecodeResult(raw []byte) (Result, error) {
	var r Result
	if len(raw) > 1<<20 {
		return r, failure("invalid_build_result")
	}
	if e := nonNullObject(raw); e != nil {
		return r, e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	r.SchemaVersion = 1
	if e := d.Decode(&r); e != nil {
		return r, failure("invalid_build_result")
	}
	if r.SchemaVersion != 1 || r.Status != "completed" {
		return r, failure("invalid_build_result")
	}
	if e := r.Binding.Validate(); e != nil {
		return r, e
	}
	if e := r.Wheel.Validate(); e != nil {
		return r, e
	}
	return r, nil
}

type Descriptor struct {
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}
type RetainedFile struct {
	Path      string
	SHA256    string
	SizeBytes int64
	Locator   string
}
type Identity struct {
	JobID, AttemptID, ComponentID string
	Epoch                         int64
}
type ArtifactReader func(context.Context, Identity, RetainedFile, int64) ([]byte, error)
type Products struct {
	Manifest     map[string]Descriptor
	Payloads     map[string][]byte
	LogicalBytes int64
}

func CollectProducts(ctx context.Context, configs map[string]Config, outputs map[string][]RetainedFile, read ArtifactReader) (Products, error) {
	result := Products{Manifest: map[string]Descriptor{}, Payloads: map[string][]byte{}}
	if len(configs) == 0 || len(configs) != len(outputs) || read == nil {
		return result, failure("build_component_plan_mismatch")
	}
	components := make([]string, 0, len(configs))
	for cid := range configs {
		components = append(components, cid)
	}
	sort.Strings(components)
	for _, cid := range components {
		cfg := configs[cid]
		if e := cfg.Validate(); e != nil {
			return result, e
		}
		if cfg.ComponentID != cid {
			return result, failure("build_component_plan_mismatch")
		}
		files, ok := outputs[cid]
		if !ok {
			return result, failure("build_component_plan_mismatch")
		}
		descriptors := map[string]RetainedFile{}
		for _, file := range files {
			if !relative(file.Path, false) || !sha256Pattern.MatchString(file.SHA256) || file.SizeBytes < 0 {
				return result, failure("invalid_build_output")
			}
			if _, exists := descriptors[file.Path]; exists {
				return result, failure("invalid_build_output")
			}
			descriptors[file.Path] = file
		}
		report, ok := descriptors["artifacts/build.json"]
		if !ok || report.SizeBytes > 1<<20 {
			return result, failure("build_result_missing")
		}
		identity := Identity{cfg.JobID, cfg.AttemptID, cid, cfg.Epoch}
		reportBytes, e := read(ctx, identity, report, 1<<20)
		if e != nil {
			return result, e
		}
		if e = verifyBytes(reportBytes, Descriptor{report.SHA256, report.SizeBytes}); e != nil {
			return result, e
		}
		built, e := DecodeResult(reportBytes)
		if e != nil {
			return result, e
		}
		if e = built.ValidateBinding(cfg); e != nil {
			return result, e
		}
		wheel, ok := descriptors["artifacts/"+built.Wheel.Filename]
		if !ok || wheel.SHA256 != built.Wheel.SHA256 || wheel.SizeBytes != built.Wheel.SizeBytes {
			return result, failure("build_product_result_mismatch")
		}
		d := Descriptor{built.Wheel.SHA256, built.Wheel.SizeBytes}
		existing, duplicate := result.Manifest[built.Wheel.Filename]
		added := d.SizeBytes
		if duplicate {
			if !reflect.DeepEqual(existing, d) {
				return result, failure("build_package_conflict")
			}
			added = 0
		}
		if added > MaxBuildBytes-result.LogicalBytes {
			return result, domain.Err(413, "build_output_disk_limit")
		}
		componentLimit := MaxBuildBytes
		for _, component := range cfg.Spec.Components {
			if component.ComponentID == cid {
				componentLimit = min(componentLimit, component.Resources.DiskBytes)
			}
		}
		if wheel.SizeBytes > componentLimit {
			return result, domain.Err(413, "build_output_disk_limit")
		}
		body, e := read(ctx, identity, wheel, componentLimit)
		if e != nil {
			return result, e
		}
		if e = verifyBytes(body, d); e != nil {
			return result, e
		}
		result.Manifest[built.Wheel.Filename] = d
		result.Payloads[built.Wheel.Filename] = body
		result.LogicalBytes += added
	}
	return result, nil
}
func verifyBytes(body []byte, expected Descriptor) error {
	digest := sha256.Sum256(body)
	if int64(len(body)) != expected.SizeBytes || hex.EncodeToString(digest[:]) != expected.SHA256 {
		return failure("build_product_changed")
	}
	return nil
}

// ValidateManifest binds participant products before network access or disk reservation.
func ValidateManifest(manifest map[string]Descriptor, limit int64) (map[string]Descriptor, error) {
	if len(manifest) > 256 || limit < 0 {
		return nil, failure("invalid_external_build_manifest")
	}
	result := map[string]Descriptor{}
	var total int64
	for name, item := range manifest {
		if !externalWheelPattern.MatchString(name) || !sha256Pattern.MatchString(item.SHA256) || item.SizeBytes < 1 || item.SizeBytes > 1<<40 {
			return nil, failure("invalid_external_build_manifest")
		}
		if item.SizeBytes > min(MaxBuildBytes, limit)-total {
			return nil, domain.Err(413, "external_build_disk_limit")
		}
		total += item.SizeBytes
		result[name] = item
	}
	return result, nil
}
func ProductsEqual(a, b map[string]Descriptor) bool { return reflect.DeepEqual(a, b) }
func ProductManifestMap(manifest map[string]Descriptor) map[string]any {
	r := map[string]any{}
	for n, d := range manifest {
		r[n] = map[string]any{"sha256": d.SHA256, "size_bytes": d.SizeBytes}
	}
	return r
}
func ParseManifest(value map[string]any, limit int64) (map[string]Descriptor, error) {
	raw, e := domain.CanonicalJSON(value)
	if e != nil {
		return nil, failure("invalid_external_build_manifest")
	}
	var result map[string]Descriptor
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if e = dec.Decode(&result); e != nil {
		return nil, failure("invalid_external_build_manifest")
	}
	return ValidateManifest(result, limit)
}
