package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

var auditOperation = regexp.MustCompile("^[A-Za-z0-9_.:-]{1,64}$")
var auditDigest = regexp.MustCompile("^[a-f0-9]{64}$")
var auditTextFields = map[string]int{"id": 256, "name": 200, "node_id": 200, "principal_id": 256, "role": 32, "status": 32, "digest": 128, "source_id": 128, "participant_id": 128, "dataset_label": 200}
var auditNumberFields = map[string]bool{"retention_days": true, "version": true, "cpu_millicores": true, "memory_bytes": true, "disk_bytes": true, "gpu_count": true, "quota_cpu_millicores": true, "quota_memory_bytes": true, "quota_disk_bytes": true, "quota_gpus": true, "max_active_jobs": true, "max_running_jobs": true, "retained_bytes": true}
var auditBoolFields = map[string]bool{"healthy": true, "quarantined": true, "enabled": true, "approved": true}
var auditListFields = map[string]bool{"gpu_uuids": true, "gpu_profiles": true, "sandbox_profiles": true, "allowed_commits": true, "allowed_hosts": true}
var auditQuotaFields = map[string]bool{"cpu_millicores": true, "memory_bytes": true, "disk_bytes": true, "gpu_count": true, "max_active_jobs": true, "max_running_jobs": true, "retained_bytes": true}

func auditText(value any, maximum int) (string, error) {
	text, ok := value.(string)
	if !ok || text == "" || !utf8.ValidString(text) || utf8.RuneCountInString(text) > maximum {
		return "", errors.New("invalid administrative audit metadata")
	}
	for _, c := range text {
		if c < 32 || c == 127 {
			return "", errors.New("invalid administrative audit metadata")
		}
	}
	lower := strings.ToLower(text)
	if strings.Contains(lower, "-----begin") || strings.HasPrefix(lower, "bearer ") || strings.HasPrefix(lower, "basic ") {
		return "", errors.New("invalid administrative audit metadata")
	}
	return text, nil
}
func validateAuditIdentity(values map[string]any) error {
	for _, name := range []string{"actor_id", "resource_id"} {
		if _, err := auditText(values[name], 256); err != nil {
			return err
		}
	}
	for _, name := range []string{"operation", "resource_type"} {
		text, ok := values[name].(string)
		if !ok || !auditOperation.MatchString(text) {
			return errors.New("invalid administrative audit identity")
		}
	}
	return nil
}
func auditInteger(value any) (int64, bool) {
	switch v := value.(type) {
	case int:
		return int64(v), v >= 0
	case int8:
		return int64(v), v >= 0
	case int16:
		return int64(v), v >= 0
	case int32:
		return int64(v), v >= 0
	case int64:
		return v, v >= 0
	case uint:
		if uint64(v) <= math.MaxInt64 {
			return int64(v), true
		}
	case uint64:
		if v <= math.MaxInt64 {
			return int64(v), true
		}
	case uint32:
		return int64(v), true
	case json.Number:
		n, err := v.Int64()
		return n, err == nil && n >= 0
	}
	return 0, false
}
func auditList(value any) (any, error) {
	if summary, ok := value.(map[string]any); ok {
		count, valid := auditInteger(summary["count"])
		digest, _ := summary["sha256"].(string)
		if len(summary) != 2 || !valid || count <= 64 || count > 1024 || !auditDigest.MatchString(digest) {
			return nil, errors.New("invalid administrative list summary")
		}
		return map[string]any{"count": count, "sha256": digest}, nil
	}
	var values []any
	switch v := value.(type) {
	case []any:
		values = v
	case []string:
		for _, item := range v {
			values = append(values, item)
		}
	default:
		return nil, errors.New("invalid administrative audit list")
	}
	if len(values) > 1024 {
		return nil, errors.New("invalid administrative audit list")
	}
	items := make([]string, len(values))
	for i, item := range values {
		text, err := auditText(item, 128)
		if err != nil {
			return nil, err
		}
		items[i] = text
	}
	if len(items) <= 64 {
		return items, nil
	}
	payload, err := domain.CanonicalJSON(items)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	return map[string]any{"count": int64(len(items)), "sha256": hex.EncodeToString(digest[:])}, nil
}

// SanitizeAuditMetadata retains only bounded known policy fields. Arbitrary
// configuration and credential-bearing fields are never traversed or stored.
func SanitizeAuditMetadata(value any) (map[string]any, error) {
	if value == nil {
		return nil, nil
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) > 128 {
		return nil, errors.New("invalid administrative audit metadata")
	}
	safe := map[string]any{}
	for key, item := range object {
		switch {
		case auditTextFields[key] > 0:
			if item == nil {
				safe[key] = nil
				continue
			}
			text, err := auditText(item, auditTextFields[key])
			if err != nil {
				return nil, err
			}
			safe[key] = text
		case auditNumberFields[key]:
			if item == nil {
				safe[key] = nil
				continue
			}
			number, ok := auditInteger(item)
			if !ok {
				return nil, errors.New("invalid administrative audit number")
			}
			safe[key] = number
		case auditBoolFields[key]:
			if _, ok := item.(bool); !ok {
				return nil, errors.New("invalid administrative audit boolean")
			}
			safe[key] = item
		case auditListFields[key]:
			values, err := auditList(item)
			if err != nil {
				return nil, err
			}
			safe[key] = values
		case key == "quotas" || key == "quotas_json":
			quotas, ok := item.(map[string]any)
			if !ok || len(quotas) > 64 {
				return nil, errors.New("invalid administrative quota metadata")
			}
			clean := map[string]any{}
			for name, number := range quotas {
				if !auditQuotaFields[name] {
					continue
				}
				if number == nil {
					clean[name] = nil
					continue
				}
				n, valid := auditInteger(number)
				if !valid {
					return nil, errors.New("invalid administrative quota number")
				}
				clean[name] = n
			}
			safe[key] = clean
		}
	}
	encoded, err := domain.CanonicalJSON(safe)
	if err != nil {
		return nil, err
	}
	if len(encoded) > 32768 {
		return nil, errors.New("administrative audit metadata is too large")
	}
	return safe, nil
}
