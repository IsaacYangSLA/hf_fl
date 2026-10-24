// Package node implements registered, certificate-bound managed node control and transport.
package node

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"net/url"
	"regexp"
	"strings"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
)

var digestPattern = regexp.MustCompile("^[a-f0-9]{64}$")
var pinnedImagePattern = regexp.MustCompile("^sha256:[a-f0-9]{64}$")

type NodeRoute struct {
	NodeID    string                  `json:"node_id"`
	PoolID    string                  `json:"pool_id"`
	Resources executor.ResourceLimits `json:"resources"`
}

func (r NodeRoute) Validate() error {
	if domain.ValidateIdentifier(r.NodeID) != nil || domain.ValidateIdentifier(r.PoolID) != nil {
		return domain.Err(409, "invalid_assignment")
	}
	return r.Resources.Defaults().Validate()
}

type NodeEndpoint struct {
	NodeID            string  `json:"node_id"`
	Origin            string  `json:"origin"`
	CAFile            string  `json:"ca_file"`
	ClientCertificate string  `json:"client_certificate"`
	ClientKey         string  `json:"client_key"`
	TimeoutSeconds    float64 `json:"timeout_seconds"`
	MaxReplyBytes     int64   `json:"max_reply_bytes"`
}

func (e NodeEndpoint) Defaults() NodeEndpoint {
	if e.TimeoutSeconds == 0 {
		e.TimeoutSeconds = 90
	}
	if e.MaxReplyBytes == 0 {
		e.MaxReplyBytes = 2 << 20
	}
	e.Origin = strings.TrimSuffix(e.Origin, "/")
	return e
}
func (e NodeEndpoint) Validate() error {
	if domain.ValidateIdentifier(e.NodeID) != nil {
		return domain.Err(409, "invalid_node_endpoint")
	}
	u, err := url.Parse(e.Origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(e.Origin, "\r\n\x00") {
		return domain.Err(409, "invalid_node_endpoint")
	}
	if e.MaxReplyBytes < 1 || e.MaxReplyBytes > 16<<20 || math.IsNaN(e.TimeoutSeconds) || math.IsInf(e.TimeoutSeconds, 0) || e.TimeoutSeconds < 1 || e.TimeoutSeconds > 300 {
		return domain.Err(409, "invalid_node_endpoint")
	}
	return nil
}

type RemoteAssignment struct {
	Identity              executor.ExecutionIdentity `json:"identity"`
	NodeID                string                     `json:"node_id"`
	PoolID                string                     `json:"pool_id"`
	Resources             executor.ResourceLimits    `json:"resources"`
	JobSpec               domain.JobSpec             `json:"job_spec"`
	ImageDigest           string                     `json:"image_digest"`
	LeaseSeconds          float64                    `json:"lease_seconds"`
	Deadline              *float64                   `json:"deadline"`
	ExternalParticipantID *string                    `json:"external_participant_id"`
	SourceLimits          map[string]int64           `json:"source_limits"`
}

func (a RemoteAssignment) Defaults() RemoteAssignment {
	a.Resources = a.Resources.Defaults()
	if a.LeaseSeconds == 0 {
		a.LeaseSeconds = 120
	}
	return a
}
func (a RemoteAssignment) Validate() error {
	if err := a.Identity.Validate(); err != nil {
		return err
	}
	if err := (NodeRoute{a.NodeID, a.PoolID, a.Resources}).Validate(); err != nil {
		return err
	}
	if err := a.JobSpec.Validate(); err != nil {
		return err
	}
	if !pinnedImagePattern.MatchString(a.ImageDigest) {
		return domain.Err(409, "image_not_pinned")
	}
	if a.LeaseSeconds <= 0 || a.LeaseSeconds > 300 || math.IsNaN(a.LeaseSeconds) || math.IsInf(a.LeaseSeconds, 0) {
		return domain.Err(409, "invalid_lease")
	}
	if a.Deadline != nil && (*a.Deadline <= 0 || math.IsNaN(*a.Deadline) || math.IsInf(*a.Deadline, 0)) {
		return domain.Err(409, "invalid_deadline")
	}
	if a.SourceLimits != nil {
		if len(a.SourceLimits) != 4 {
			return domain.Err(409, "invalid_assignment")
		}
		for _, key := range []string{"max_bytes", "max_files", "max_git_bytes", "max_git_files"} {
			v, ok := a.SourceLimits[key]
			if !ok || v < 1 || v > 1<<40 {
				return domain.Err(409, "invalid_assignment")
			}
		}
	}
	if a.ExternalParticipantID != nil {
		if domain.ValidateIdentifier(*a.ExternalParticipantID) != nil {
			return domain.Err(409, "invalid_assignment")
		}
		found := false
		for _, p := range a.JobSpec.Participants {
			if p.ParticipantID == *a.ExternalParticipantID && p.Mode == "external" {
				found = true
			}
		}
		if !found || a.Identity.ComponentID != ExternalComponent(*a.ExternalParticipantID) {
			return domain.Err(409, "invalid_assignment")
		}
	} else {
		c, ok := a.Component()
		if !ok || c.Resources.PoolID != a.PoolID {
			return domain.Err(409, "invalid_assignment")
		}
		if c.Resources.CPUMillicores != a.Resources.CPUMillis || c.Resources.MemoryBytes != a.Resources.MemoryBytes || c.Resources.DiskBytes != a.Resources.DiskBytes || c.Resources.GPUCount != a.Resources.GPUs {
			return domain.Err(409, "invalid_resources")
		}
	}
	return nil
}
func (a RemoteAssignment) Component() (domain.ComponentSpec, bool) {
	if a.ExternalParticipantID != nil {
		return domain.ComponentSpec{ComponentID: a.Identity.ComponentID, Role: "participant", ParticipantID: a.ExternalParticipantID}, true
	}
	for _, c := range a.JobSpec.Components {
		if c.ComponentID == a.Identity.ComponentID {
			return c, true
		}
	}
	return domain.ComponentSpec{}, false
}
func ExternalComponent(participant string) string {
	b, _ := domain.CanonicalJSON([]any{participant})
	h := sha256.Sum256(b)
	return "participant-" + hex.EncodeToString(h[:])[:40]
}
func DecodeAssignment(b []byte) (RemoteAssignment, error) {
	var a RemoteAssignment
	if err := strictDecode(b, &a); err != nil {
		return a, domain.Err(422, "invalid_assignment")
	}
	// The wire format always carries these fields; missing and explicit null must not loosen immutable limits.
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(b, &fields)
	for _, key := range []string{"identity", "node_id", "pool_id", "resources", "job_spec", "image_digest"} {
		v, ok := fields[key]
		if !ok || string(v) == "null" {
			return a, domain.Err(422, "invalid_assignment")
		}
	}
	if raw, ok := fields["lease_seconds"]; ok && string(raw) == "null" {
		return a, domain.Err(422, "invalid_assignment")
	}
	a = a.Defaults()
	return a, a.Validate()
}
func strictDecode(data []byte, to any) error {
	if _, err := domain.DecodeJSON(data); err != nil {
		return err
	}
	if err := uniqueJSON(data); err != nil {
		return err
	}

	d := json.NewDecoder(strings.NewReader(string(data)))
	d.UseNumber()
	d.DisallowUnknownFields()
	if err := d.Decode(to); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return domain.Err(422, "invalid_assignment")
	}
	return nil
}
func Thumbprint(der []byte) string {
	h := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(h[:])
}
func validateThumbprint(value string) error {
	b, e := base64.RawURLEncoding.DecodeString(value)
	if e != nil || len(value) != 43 || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != value {
		return domain.Err(422, "invalid_node_certificate")
	}
	return nil
}

type NodePurgeReceipt struct {
	JobID                     string `json:"job_id"`
	AttemptID                 string `json:"attempt_id"`
	ComponentID               string `json:"component_id"`
	Epoch                     int64  `json:"epoch"`
	NodeID                    string `json:"node_id"`
	PoolID                    string `json:"pool_id"`
	SpecDigest                string `json:"spec_digest"`
	OperationID               string `json:"operation_id"`
	Purpose                   string `json:"purpose"`
	TerminationConfirmed      bool   `json:"termination_confirmed"`
	SourceDeleted             bool   `json:"source_deleted"`
	ConfigDeleted             bool   `json:"config_deleted"`
	BuildDeleted              bool   `json:"build_deleted"`
	PrivateCredentialsDeleted bool   `json:"private_credentials_deleted"`
	PrivateSecretsDeleted     bool   `json:"private_secrets_deleted"`
	RetainedDeleted           bool   `json:"retained_deleted"`
	AuxiliaryDeleted          bool   `json:"auxiliary_deleted"`
	Confirmed                 bool   `json:"confirmed"`
}

func (r NodePurgeReceipt) Identity() executor.ExecutionIdentity {
	return executor.ExecutionIdentity{JobID: r.JobID, AttemptID: r.AttemptID, ComponentID: r.ComponentID, Epoch: r.Epoch}
}
func (r NodePurgeReceipt) Validate() error {
	if r.Identity().Validate() != nil || domain.ValidateIdentifier(r.NodeID) != nil || domain.ValidateIdentifier(r.PoolID) != nil || !digestPattern.MatchString(r.SpecDigest) || r.OperationID != "purge-"+r.Identity().Key() || r.Purpose != "managed_node_purge" || !r.TerminationConfirmed || !r.SourceDeleted || !r.ConfigDeleted || !r.BuildDeleted || !r.PrivateCredentialsDeleted || !r.PrivateSecretsDeleted || !r.RetainedDeleted || !r.AuxiliaryDeleted || !r.Confirmed {
		return domain.Err(409, "invalid_purge_receipt")
	}
	return nil
}

// uniqueJSON rejects ambiguous duplicate object fields before typed decoding.
func uniqueJSON(data []byte) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 128 {
			return domain.Err(422, "invalid_assignment")
		}
		token, e := decoder.Token()
		if e != nil {
			return e
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		if delim == '{' {
			seen := map[string]bool{}
			for decoder.More() {
				key, e := decoder.Token()
				if e != nil {
					return e
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return domain.Err(422, "invalid_assignment")
				}
				seen[name] = true
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
			end, e := decoder.Token()
			if e != nil || end != json.Delim('}') {
				return domain.Err(422, "invalid_assignment")
			}
		} else if delim == '[' {
			for decoder.More() {
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
			end, e := decoder.Token()
			if e != nil || end != json.Delim(']') {
				return domain.Err(422, "invalid_assignment")
			}
		} else {
			return domain.Err(422, "invalid_assignment")
		}
		return nil
	}
	if e := walk(0); e != nil {
		return e
	}
	if _, e := decoder.Token(); e != io.EOF {
		return domain.Err(422, "invalid_assignment")
	}
	return nil
}
