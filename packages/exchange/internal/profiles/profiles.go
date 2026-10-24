// Package profiles defines the static, trusted Exchange application policies.
// Profiles add constraints to core authorization; they never execute ML code.
package profiles

import (
	"encoding/json"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
)

type Profile interface {
	Name() string
	PolicyDefaults(string) domain.Object
	ValidatePolicy(string, []string, string) error
	ValidateBindings(domain.Object, []domain.Object) error
	RecordBaseID(string, domain.Object) any
	ValidatePublish(string, domain.Object, domain.Object, domain.Object) error
	SelectionSpec(string, any) domain.Object
	InputEligible(domain.Object, domain.Object) bool
	ValidateInputCurrent(domain.Object, domain.Object) error
	CompletionInputs(domain.Object, []domain.Object, string) ([]domain.Object, error)
	ValidateType(string, domain.Object) error
	ValidateRecord(string, domain.Object, domain.Object) error
	ValidateReference(string, domain.Object, []domain.Object, any) error
	SelectInputs([]domain.Object, any) []domain.Object
}

type profile struct {
	name    string
	minimum int
}

func Names() []string { return []string{"generic.v1", "fedavg.v1"} }
func Get(name any) (Profile, error) {
	s, ok := name.(string)
	if !ok {
		return nil, domain.Err(422, "unknown_profile")
	}
	switch s {
	case "generic.v1":
		return profile{name: s}, nil
	case "fedavg.v1":
		return profile{name: s, minimum: 2}, nil
	}
	return nil, domain.Err(422, "unknown_profile")
}
func (p profile) Name() string { return p.name }
func (p profile) fedavg() bool { return p.name == "fedavg.v1" }
func (p profile) PolicyDefaults(kind string) domain.Object {
	if p.fedavg() {
		switch kind {
		case "training.update":
			return domain.Object{"publish_roles": []string{"contributor"}, "visibility": "private"}
		case "model.global":
			return domain.Object{"publish_roles": []string{"publisher"}, "visibility": "shared"}
		}
	}
	return domain.Object{"publish_roles": []string{"contributor", "publisher"}, "visibility": "shared"}
}
func onlyRole(roles []string, role string) bool {
	if len(roles) == 0 {
		return false
	}
	for _, r := range roles {
		if r != role {
			return false
		}
	}
	return true
}
func (p profile) ValidatePolicy(kind string, roles []string, visibility string) error {
	if p.fedavg() && ((kind == "model.global" && (!onlyRole(roles, "publisher") || visibility != "shared")) || (kind == "training.update" && !onlyRole(roles, "contributor"))) {
		return domain.Err(422, "profile_policy_conflict")
	}
	return nil
}
func object(v any) domain.Object {
	if m, ok := v.(map[string]any); ok && m != nil {
		return m
	}
	return domain.Object{}
}
func metadata(record domain.Object) domain.Object {
	if v, ok := record["metadata"]; ok {
		return object(v)
	}
	return object(record["metadata_json"])
}
func bindings(record domain.Object) domain.Object {
	if v, ok := record["creator_bindings"]; ok {
		return object(v)
	}
	return object(record["attribution"])
}
func participant(b domain.Object) (string, bool) {
	s, ok := b["participant"].(string)
	return s, ok && s != "" && utf8.RuneCountInString(s) <= 128
}
func (p profile) ValidateBindings(b domain.Object, others []domain.Object) error {
	if !p.fedavg() || b["participant"] == nil {
		return nil
	}
	s, ok := participant(b)
	if !ok {
		return domain.Err(422, "invalid_participant")
	}
	for _, o := range others {
		if other, ok := o["participant"].(string); ok && other == s {
			return domain.Err(409, "participant_already_bound")
		}
	}
	return nil
}
func (p profile) RecordBaseID(kind string, m domain.Object) any {
	if p.fedavg() && (kind == "training.update" || kind == "model.global") {
		return m["base_record_id"]
	}
	return nil
}
func (p profile) ValidatePublish(kind string, m, recordBindings, currentBindings domain.Object) error {
	if !p.fedavg() {
		return nil
	}
	if err := p.ValidateRecord(kind, m, recordBindings); err != nil {
		return err
	}
	if kind == "training.update" && !equal(recordBindings, currentBindings) {
		return domain.Err(409, "participant_binding_changed")
	}
	return nil
}
func (p profile) SelectionSpec(name string, baseID any) domain.Object {
	if p.fedavg() && name == "main" {
		return domain.Object{"kind": "training.update", "base_id": baseID, "minimum": p.minimum, "minimum_error": "insufficient_participants"}
	}
	return nil
}
func (p profile) InputEligible(record, member domain.Object) bool {
	if !p.fedavg() || record["kind"] != "training.update" {
		return true
	}
	if member == nil {
		return false
	}
	roles, ok := domain.Strings(member["roles"])
	if !ok {
		return false
	}
	eligible := false
	for _, r := range roles {
		eligible = eligible || r == "contributor"
	}
	return eligible && equal(object(member["bindings"]), bindings(record))
}
func (p profile) ValidateInputCurrent(record, member domain.Object) error {
	if !p.InputEligible(record, member) {
		return domain.Err(409, "input_participant_revoked")
	}
	return nil
}
func copyRecords(in []domain.Object) []domain.Object { return append([]domain.Object{}, in...) }
func (p profile) CompletionInputs(result domain.Object, frozen []domain.Object, name string) ([]domain.Object, error) {
	if !p.fedavg() || name != "main" {
		return copyRecords(frozen), nil
	}
	m := metadata(result)
	var declared []string
	if v, ok := m["inputs"]; ok {
		var valid bool
		declared, valid = domain.Strings(v)
		if !valid {
			return nil, domain.Err(409, "invalid_result_inputs")
		}
	}
	seen := map[string]bool{}
	byID := map[string]domain.Object{}
	for _, r := range frozen {
		id, _ := r["id"].(string)
		byID[id] = r
	}
	used := make([]domain.Object, 0, len(declared))
	participants := map[string]bool{}
	for _, id := range declared {
		if seen[id] {
			return nil, domain.Err(409, "invalid_result_inputs")
		}
		seen[id] = true
	}
	for _, id := range declared {
		r, ok := byID[id]
		if !ok {
			return nil, domain.Err(409, "result_provenance_mismatch")
		}
		used = append(used, r)
	}
	for _, r := range used {
		s, ok := bindings(r)["participant"].(string)
		if !ok || participants[s] {
			return nil, domain.Err(409, "insufficient_participants")
		}
		participants[s] = true
	}
	if len(used) < p.minimum {
		return nil, domain.Err(409, "insufficient_participants")
	}
	return used, nil
}

var annotations = map[string]bool{"title": true, "description": true, "$comment": true, "examples": true, "default": true}

func (p profile) ValidateType(kind string, s domain.Object) error {
	if !p.fedavg() || (kind != "training.update" && kind != "model.global") {
		return nil
	}
	allowed := map[string]bool{"$schema": true, "type": true, "properties": true, "required": true, "additionalProperties": true}
	for k := range s {
		if !allowed[k] && !annotations[k] {
			return domain.Err(422, "profile_schema_conflict")
		}
	}
	additional := true
	if v, ok := s["additionalProperties"]; ok {
		var valid bool
		additional, valid = v.(bool)
		if !valid {
			return domain.Err(422, "profile_schema_conflict")
		}
	}
	expected := [][2]string{{"base_record_id", "string"}, {"sample_count", "integer"}}
	if kind == "model.global" {
		expected = [][2]string{{"inputs", "array"}, {"base_record_id", "string"}}
	}
	properties := object(s["properties"])
	for _, field := range expected {
		v, present := properties[field[0]]
		if !present {
			if !additional {
				return domain.Err(422, "profile_schema_conflict", field[0])
			}
			continue
		}
		spec, ok := v.(map[string]any)
		if !ok || spec["type"] != field[1] {
			return domain.Err(422, "profile_schema_conflict", field[0])
		}
		for k := range spec {
			if k != "type" && !annotations[k] {
				return domain.Err(422, "profile_schema_conflict", field[0])
			}
		}
	}
	return nil
}
func (p profile) ValidateRecord(kind string, m, b domain.Object) error {
	if !p.fedavg() {
		return nil
	}
	switch kind {
	case "training.update":
		if _, ok := participant(b); !ok {
			return domain.Err(422, "participant_binding_required")
		}
		if base, ok := m["base_record_id"].(string); !ok || base == "" {
			return domain.Err(422, "round_base_required")
		}
		count, ok := domain.Integer(m["sample_count"])
		if !ok || count.Sign() < 1 {
			return domain.Err(422, "invalid_sample_count")
		}
		if _, present := m["participant"]; present {
			return domain.Err(422, "participant_is_server_attributed")
		}
	case "model.global":
		if v, present := m["inputs"]; present {
			values, ok := domain.Strings(v)
			if !ok {
				return domain.Err(422, "invalid_result_inputs")
			}
			seen := map[string]bool{}
			for _, id := range values {
				if id == "" || seen[id] {
					return domain.Err(422, "invalid_result_inputs")
				}
				seen[id] = true
			}
		}
		if v := m["base_record_id"]; v != nil {
			if _, ok := v.(string); !ok {
				return domain.Err(422, "invalid_round_base")
			}
		}
	}
	return nil
}
func (p profile) ValidateReference(name string, record domain.Object, inputs []domain.Object, baseID any) error {
	if !p.fedavg() || name != "main" {
		return nil
	}
	if record["kind"] != "model.global" {
		return domain.Err(422, "profile_reference_kind")
	}
	m := metadata(record)
	declared := []string{}
	if v, ok := m["inputs"]; ok {
		var good bool
		declared, good = domain.Strings(v)
		if !good {
			return domain.Err(409, "result_provenance_mismatch")
		}
	}
	if baseID == nil {
		if m["base_record_id"] != nil || len(declared) > 0 {
			return domain.Err(409, "initial_model_has_provenance")
		}
		return nil
	}
	if len(inputs) == 0 {
		return domain.Err(409, "coordination_required")
	}
	if len(inputs) < p.minimum {
		return domain.Err(409, "insufficient_participants")
	}
	participants := map[string]bool{}
	expected := map[string]bool{}
	for _, item := range inputs {
		part, ok := bindings(item)["participant"].(string)
		if item["kind"] != "training.update" || !equal(metadata(item)["base_record_id"], baseID) || !ok || part == "" || participants[part] {
			return domain.Err(409, "invalid_round_inputs")
		}
		participants[part] = true
		id, _ := item["id"].(string)
		expected[id] = true
	}
	actual := map[string]bool{}
	for _, id := range declared {
		actual[id] = true
	}
	if !equal(m["base_record_id"], baseID) || !reflect.DeepEqual(expected, actual) {
		return domain.Err(409, "result_provenance_mismatch")
	}
	return nil
}
func (p profile) SelectInputs(records []domain.Object, baseID any) []domain.Object {
	if !p.fedavg() {
		return copyRecords(records)
	}
	selected := map[string]domain.Object{}
	for _, r := range records {
		if state, present := r["state"]; present && state != "published" {
			continue
		}
		if r["kind"] != "training.update" || !equal(metadata(r)["base_record_id"], baseID) {
			continue
		}
		participant, ok := bindings(r)["participant"].(string)
		if !ok || participant == "" {
			continue
		}
		previous, exists := selected[participant]
		published, _ := domain.Float(r["published_at"])
		previousPublished, _ := domain.Float(previous["published_at"])
		id, _ := r["id"].(string)
		oldID, _ := previous["id"].(string)
		if !exists || published > previousPublished || (published == previousPublished && id > oldID) {
			selected[participant] = r
		}
	}
	names := make([]string, 0, len(selected))
	for n := range selected {
		names = append(names, n)
	}
	sort.Strings(names)
	result := make([]domain.Object, 0, len(names))
	for _, n := range names {
		result = append(result, selected[n])
	}
	return result
}

// Python dictionaries compare numeric JSON values by value rather than Go type.
func rational(v any) (*big.Rat, bool) {
	switch n := v.(type) {
	case bool:
		if n {
			return new(big.Rat).SetInt64(1), true
		}
		return new(big.Rat), true
	case json.Number:
		if strings.ContainsAny(string(n), ".eE") {
			f, err := strconv.ParseFloat(string(n), 64)
			if err != nil {
				return nil, false
			}
			r := new(big.Rat).SetFloat64(f)
			return r, r != nil
		}
	}
	if i, ok := domain.Integer(v); ok {
		return new(big.Rat).SetInt(i), true
	}
	if f, ok := domain.Float(v); ok {
		r := new(big.Rat).SetFloat64(f)
		return r, r != nil
	}
	return nil, false
}
func equal(a, b any) bool {
	if x, ok := rational(a); ok {
		if y, ok := rational(b); ok {
			return x.Cmp(y) == 0
		}
		return false
	}
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, present := y[k]
			if !present || !equal(v, w) {
				return false
			}
		}
		return true
	}
	left, right := reflect.ValueOf(a), reflect.ValueOf(b)
	if left.IsValid() && right.IsValid() && (left.Kind() == reflect.Slice || left.Kind() == reflect.Array) && (right.Kind() == reflect.Slice || right.Kind() == reflect.Array) {
		if left.Len() != right.Len() {
			return false
		}
		for i := 0; i < left.Len(); i++ {
			if !equal(left.Index(i).Interface(), right.Index(i).Interface()) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(a, b)
}
