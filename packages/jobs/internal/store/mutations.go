package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

// Insert applies the reference ORM's client defaults to values before writing.
// Generated IDs and timestamps are reflected in the caller's map, just as the
// reference model receives its generated values on flush.
func (tx *Tx) Insert(ctx context.Context, table string, values map[string]any) error {
	if err := loadSchema(); err != nil {
		return err
	}
	spec, ok := schemaTables[table]
	if !ok {
		return errors.New("unknown manager table")
	}
	if values == nil {
		return errors.New("manager insert values are required")
	}
	known := map[string]columnSpec{}
	for _, col := range spec.Columns {
		known[col.Name] = col
	}
	for name := range values {
		if _, ok := known[name]; !ok {
			return errors.New("unknown manager column")
		}
	}
	for _, col := range spec.Columns {
		if _, ok := values[col.Name]; ok {
			continue
		}
		if col.Default != nil {
			switch col.Default.Kind {
			case "id":
				id := make([]byte, 16)
				if _, err := rand.Read(id); err != nil {
					return err
				}
				values[col.Name] = hex.EncodeToString(id)
			case "now":
				values[col.Name] = time.Now().UTC()
			case "map":
				values[col.Name] = map[string]any{}
			case "list":
				values[col.Name] = []any{}
			case "value":
				values[col.Name] = col.Default.Value
			default:
				return errors.New("unknown embedded manager default")
			}
		} else if !col.Nullable {
			return fmt.Errorf("missing required manager column %s", col.Name)
		}
	}
	if err := validateMutation(table, values, false); err != nil {
		return err
	}
	keys := make([]string, 0, len(values))
	for name := range values {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	names := make([]string, len(keys))
	marks := make([]string, len(keys))
	args := make([]any, len(keys))
	for i, key := range keys {
		value, err := columnValue(known[key], values[key])
		if err != nil {
			return err
		}
		names[i] = quoteID(key)
		marks[i] = "?"
		args[i] = value
	}
	_, err := tx.Exec(ctx, "INSERT INTO "+quoteID(table)+" ("+strings.Join(names, ",")+") VALUES ("+strings.Join(marks, ",")+")", args...)
	return err
}

// Update restricts mutations to explicit selected rows. It enforces the
// reference ORM's immutable job provenance and append-only audit rules.
func (tx *Tx) Update(ctx context.Context, table string, where, values map[string]any) error {
	if err := loadSchema(); err != nil {
		return err
	}
	spec, ok := schemaTables[table]
	if !ok {
		return errors.New("unknown manager table")
	}
	if len(where) == 0 || len(values) == 0 {
		return errors.New("manager updates require selection and values")
	}
	if err := validateMutation(table, values, true); err != nil {
		return err
	}
	known := map[string]columnSpec{}
	for _, col := range spec.Columns {
		known[col.Name] = col
	}
	for name := range values {
		if _, ok := known[name]; !ok {
			return errors.New("unknown manager column")
		}
	}
	for name := range where {
		if _, ok := known[name]; !ok {
			return errors.New("unknown manager selection column")
		}
	}
	keys := sortedKeys(values)
	conditions := sortedKeys(where)
	set := []string{}
	parts := []string{}
	args := []any{}
	for _, key := range keys {
		value, err := columnValue(known[key], values[key])
		if err != nil {
			return err
		}
		set = append(set, quoteID(key)+"=?")
		args = append(args, value)
	}
	for _, key := range conditions {
		if where[key] == nil {
			parts = append(parts, quoteID(key)+" IS NULL")
			continue
		}
		value, err := columnValue(known[key], where[key])
		if err != nil {
			return err
		}
		parts = append(parts, quoteID(key)+"=?")
		args = append(args, value)
	}
	_, err := tx.Exec(ctx, "UPDATE "+quoteID(table)+" SET "+strings.Join(set, ",")+" WHERE "+strings.Join(parts, " AND "), args...)
	return err
}
func sortedKeys(value map[string]any) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
func columnValue(col columnSpec, value any) (any, error) {
	if value == nil {
		if !col.Nullable {
			return nil, errors.New("null nonnullable manager column")
		}
		return nil, nil
	}
	switch col.Kind {
	case "json":
		if text, ok := value.(string); ok {
			decoded, err := domain.DecodeJSON([]byte(text))
			if err != nil {
				return nil, errors.New("invalid manager JSON column")
			}
			return JSON(decoded)
		}
		if bytes, ok := value.(json.RawMessage); ok {
			decoded, err := domain.DecodeJSON(bytes)
			if err != nil {
				return nil, errors.New("invalid manager JSON column")
			}
			return JSON(decoded)
		}
		return JSON(value)
	case "time":
		t, ok := Time(value)
		if !ok {
			return nil, errors.New("invalid manager timestamp")
		}
		return t, nil
	case "bool":
		if _, ok := value.(bool); !ok {
			return nil, errors.New("invalid manager boolean")
		}
	}
	return value, nil
}
func validateMutation(table string, values map[string]any, update bool) error {
	if table == "jm_admin_audit" {
		if update {
			return errors.New("administrative audit history is append-only")
		}
		if err := validateAuditIdentity(values); err != nil {
			return err
		}
		for _, name := range []string{"before_json", "after_json"} {
			safe, err := SanitizeAuditMetadata(values[name])
			if err != nil {
				return err
			}
			values[name] = safe
		}
	}
	if update && table == "jm_jobs" {
		for _, name := range []string{"spec_json", "spec_hash", "project_id", "creator_id", "target_round"} {
			if _, ok := values[name]; ok {
				return errors.New("job specification and provenance are immutable")
			}
		}
	}
	if table == "jm_artifacts" {
		if value, ok := values["locator_json"]; ok && value != nil {
			var object map[string]any
			switch v := value.(type) {
			case map[string]any:
				object = v
			case string:
				decoded, err := domain.DecodeJSON([]byte(v))
				if err != nil {
					return errors.New("invalid trusted artifact locator")
				}
				object, _ = decoded.(map[string]any)
			default:
				return errors.New("invalid trusted artifact locator")
			}
			if object == nil {
				return errors.New("invalid trusted artifact locator")
			}
			locator, err := domain.LocatorFromMap(object)
			if err != nil {
				return err
			}
			values["locator_json"] = locator.Map()
		}
	}
	return nil
}
