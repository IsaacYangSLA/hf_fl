// Package httpapi implements Exchange's ordinary and managed HTTP contracts.
package httpapi

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
)

// The same contract drives the actual request validator and the exported docs.
// This is the existing public wire contract; operator/private routes are separate.
//
//go:embed openapi.json
var openAPIData []byte

type object = domain.Object
type compiledContract struct {
	document   object
	schemas    map[string]any
	operations map[string]object
}

var contractOnce sync.Once
var contractValue *compiledContract
var contractError error

// OpenAPI returns the public contract without initializing services or contacting
// databases, identity providers, or object storage.
func OpenAPI() ([]byte, error) {
	if _, err := publicContract(); err != nil {
		return nil, err
	}
	return append([]byte(nil), openAPIData...), nil
}
func publicContract() (*compiledContract, error) {
	contractOnce.Do(func() { contractValue, contractError = compileContract(openAPIData) })
	return contractValue, contractError
}
func compileContract(data []byte) (*compiledContract, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc object
	if err := dec.Decode(&doc); err != nil {
		return nil, errors.New("invalid embedded Exchange HTTP contract")
	}
	components, ok := doc["components"].(map[string]any)
	if !ok {
		return nil, errors.New("missing HTTP contract components")
	}
	schemas, ok := components["schemas"].(map[string]any)
	if !ok {
		return nil, errors.New("missing HTTP contract schemas")
	}
	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		return nil, errors.New("missing HTTP contract paths")
	}
	c := &compiledContract{document: doc, schemas: schemas, operations: map[string]object{}}
	for path, item := range paths {
		methods, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("invalid HTTP contract path")
		}
		for method, raw := range methods {
			op, ok := raw.(map[string]any)
			if !ok {
				return nil, errors.New("invalid HTTP contract operation")
			}
			key := strings.ToUpper(method) + " " + path
			c.operations[key] = op
			for _, rawParameter := range anySlice(op["parameters"]) {
				parameter, ok := rawParameter.(map[string]any)
				if !ok {
					return nil, errors.New("invalid HTTP parameter")
				}
				parameterSchema, ok := parameter["schema"].(map[string]any)
				if !ok {
					return nil, errors.New("invalid HTTP parameter schema")
				}
				if err := c.checkSchema(parameterSchema, map[string]bool{}); err != nil {
					return nil, err
				}
			}

			if body, ok := op["requestBody"].(map[string]any); ok {
				content, _ := body["content"].(map[string]any)
				media, _ := content["application/json"].(map[string]any)
				schema, ok := media["schema"].(map[string]any)
				if !ok {
					return nil, errors.New("invalid request body contract")
				}
				if err := c.checkSchema(schema, map[string]bool{}); err != nil {
					return nil, err
				}
			}
		}
	}
	expected := map[string]bool{}
	for _, r := range routeSpecs {
		expected[r.method+" "+r.path] = true
	}
	if len(c.operations) != len(expected) {
		return nil, errors.New("HTTP route inventory differs from embedded contract")
	}
	for key := range expected {
		if _, ok := c.operations[key]; !ok {
			return nil, errors.New("HTTP route missing from embedded contract")
		}
	}
	return c, nil
}

var wireKeywords = map[string]bool{"$ref": true, "type": true, "properties": true, "required": true, "additionalProperties": true,
	"anyOf": true, "items": true, "default": true, "enum": true, "title": true, "minLength": true, "maxLength": true,
	"minItems": true, "maxItems": true, "minimum": true, "maximum": true, "exclusiveMinimum": true, "pattern": true}

func (c *compiledContract) checkSchema(schema object, seen map[string]bool) error {
	if raw, exists := schema["type"]; exists {
		kind, ok := raw.(string)
		if !ok {
			return errors.New("unsupported HTTP schema type")
		}
		switch kind {
		case "object", "array", "string", "integer", "number", "null", "boolean":
		default:
			return errors.New("unsupported HTTP schema type")
		}
	}
	if raw, exists := schema["additionalProperties"]; exists {
		if _, ok := raw.(bool); !ok {
			return errors.New("unsupported HTTP dictionary constraint")
		}
	}
	for _, key := range []string{"minLength", "maxLength", "minItems", "maxItems"} {
		if raw, exists := schema[key]; exists {
			n, ok := wireInt(raw)
			if !ok || n < 0 {
				return errors.New("invalid HTTP size constraint")
			}
		}
	}
	for _, key := range []string{"minimum", "maximum", "exclusiveMinimum"} {
		if raw, exists := schema[key]; exists {
			if _, ok := new(big.Rat).SetString(fmt.Sprint(raw)); !ok {
				return errors.New("invalid HTTP numeric constraint")
			}
		}
	}
	if raw, exists := schema["required"]; exists {
		list, ok := raw.([]any)
		if !ok {
			return errors.New("invalid HTTP required fields")
		}
		for _, key := range list {
			if _, ok := key.(string); !ok {
				return errors.New("invalid HTTP required field")
			}
		}
	}
	if raw, exists := schema["properties"]; exists {
		if _, ok := raw.(map[string]any); !ok {
			return errors.New("invalid HTTP object fields")
		}
	}
	if raw, exists := schema["enum"]; exists {
		list, ok := raw.([]any)
		if !ok || len(list) == 0 {
			return errors.New("invalid HTTP enumeration")
		}
		for _, item := range list {
			switch item.(type) {
			case nil, string, bool, json.Number:
			default:
				return errors.New("unsupported HTTP enum value")
			}
		}
	}

	for key := range schema {
		if !wireKeywords[key] {
			return fmt.Errorf("unsupported HTTP request schema keyword: %s", key)
		}
	}
	if raw, ok := schema["$ref"]; ok {
		ref, ok := raw.(string)
		if !ok || !strings.HasPrefix(ref, "#/components/schemas/") {
			return errors.New("invalid HTTP request schema reference")
		}
		if seen[ref] {
			return errors.New("recursive HTTP request schema")
		}
		target, ok := c.schemas[strings.TrimPrefix(ref, "#/components/schemas/")].(map[string]any)
		if !ok {
			return errors.New("missing HTTP request schema")
		}
		next := map[string]bool{}
		for k, v := range seen {
			next[k] = v
		}
		next[ref] = true
		if err := c.checkSchema(target, next); err != nil {
			return err
		}
	}
	if p, ok := schema["properties"].(map[string]any); ok {
		for _, raw := range p {
			child, ok := raw.(map[string]any)
			if !ok {
				return errors.New("invalid HTTP property")
			}
			if err := c.checkSchema(child, seen); err != nil {
				return err
			}
		}
	}
	if raw, ok := schema["items"]; ok {
		child, ok := raw.(map[string]any)
		if !ok {
			return errors.New("invalid HTTP array item")
		}
		if err := c.checkSchema(child, seen); err != nil {
			return err
		}
	}
	if raw, ok := schema["anyOf"]; ok {
		list, ok := raw.([]any)
		if !ok {
			return errors.New("invalid HTTP union")
		}
		for _, raw := range list {
			child, ok := raw.(map[string]any)
			if !ok {
				return errors.New("invalid HTTP union item")
			}
			if err := c.checkSchema(child, seen); err != nil {
				return err
			}
		}
	}
	if raw, ok := schema["pattern"]; ok {
		pattern, ok := raw.(string)
		if !ok {
			return errors.New("invalid HTTP pattern")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return errors.New("unsupported HTTP pattern")
		}
	}
	return nil
}
func (c *compiledContract) bodySchema(spec routeSpec) object {
	op := c.operations[spec.method+" "+spec.path]
	body, _ := op["requestBody"].(map[string]any)
	content, _ := body["content"].(map[string]any)
	media, _ := content["application/json"].(map[string]any)
	schema, _ := media["schema"].(map[string]any)
	return schema
}
func (c *compiledContract) validateBody(spec routeSpec, value any) (object, []string) {
	schema := c.bodySchema(spec)
	v, problems := c.validate(schema, value, "body")
	body, _ := v.(map[string]any)
	return body, problems
}

var propertyOrder = map[string][]string{
	"SpaceBody":          {"name", "profile", "quota_bytes", "principal_quota_bytes", "quota_records", "quota_metadata_bytes"},
	"SpaceLimitsBody":    {"quota_bytes", "principal_quota_bytes", "quota_records", "quota_metadata_bytes"},
	"ManagedSpaceBody":   {"job_id"},
	"WorkloadGrantBody":  {"subject", "job_id", "attempt_id", "component_id", "epoch", "expires_at", "certificate_thumbprint", "roles", "bindings"},
	"RevokeWorkloadBody": {"attempt_id"}, "MemberBody": {"roles", "subject", "bindings"},
	"PolicyBody": {"publish_roles", "visibility"}, "TypeBody": {"publish_roles", "visibility", "schema"},
	"AttachmentBody": {"path", "size", "sha256", "media_type"}, "RecordBody": {"kind", "schema_revision_id", "metadata", "attachments"},
	"PatchBody": {"metadata"}, "ReferenceBody": {"record_id"},
	"AcquisitionBody": {"reference", "expected_token", "input_record_ids", "lease_seconds"},
	"FenceBody":       {"fence"}, "CompletionBody": {"fence", "result_record_id"}, "GrantsBody": {"numbers"},
}
var factoryDefaults = map[string]object{
	"WorkloadGrantBody": {"bindings": object{}},
	"MemberBody":        {"bindings": object{}},
	"PolicyBody":        {"publish_roles": []any{"contributor", "publisher"}},
	"RecordBody":        {"metadata": object{}, "attachments": []any{}},
	"AcquisitionBody":   {"input_record_ids": []any{}},
}

func (c *compiledContract) validate(schema object, value any, location string) (any, []string) {
	if ref, ok := schema["$ref"].(string); ok {
		target, _ := c.schemas[strings.TrimPrefix(ref, "#/components/schemas/")].(map[string]any)
		return c.validate(target, value, location)
	}
	if alternatives, ok := schema["anyOf"].([]any); ok {
		for _, raw := range alternatives {
			candidate, _ := raw.(map[string]any)
			if out, errors := c.validate(candidate, value, location); len(errors) == 0 {
				return out, nil
			}
		}
		return nil, []string{location}
	}
	kind, _ := schema["type"].(string)
	switch kind {
	case "null":
		if value != nil {
			return nil, []string{location}
		}
		return nil, nil
	case "object":
		data, ok := value.(map[string]any)
		if !ok {
			return nil, []string{location}
		}
		properties, hasProperties := schema["properties"].(map[string]any)
		// Dictionary fields carry arbitrary values; model_dump(exclude_none=True)
		// removes None model fields, never None entries inside metadata/bindings/schema.
		if !hasProperties {
			return data, nil
		}
		title, _ := schema["title"].(string)
		order := append([]string{}, propertyOrder[title]...)
		present := map[string]bool{}
		for _, key := range order {
			present[key] = true
		}
		rest := []string{}
		for key := range properties {
			if !present[key] {
				rest = append(rest, key)
			}
		}
		sort.Strings(rest)
		order = append(order, rest...)
		required := map[string]bool{}
		for _, v := range anySlice(schema["required"]) {
			if key, ok := v.(string); ok {
				required[key] = true
			}
		}
		out := object{}
		problems := []string{}
		for _, key := range order {
			child, _ := properties[key].(map[string]any)
			raw, exists := data[key]
			if !exists {
				if def, ok := child["default"]; ok {
					if def != nil {
						out[key] = cloneWire(def)
					}
					continue
				}
				if def, ok := factoryDefaults[title][key]; ok {
					out[key] = cloneWire(def)
					continue
				}
				if required[key] {
					problems = append(problems, location+"."+key)
				}
				continue
			}
			parsed, errs := c.validate(child, raw, location+"."+key)
			problems = append(problems, errs...)
			if len(errs) == 0 && parsed != nil {
				out[key] = parsed
			}
		}
		extra := []string{}
		for key := range data {
			if _, ok := properties[key]; !ok {
				extra = append(extra, key)
			}
		}
		sort.Strings(extra)
		forbid, _ := schema["additionalProperties"].(bool)
		for _, key := range extra {
			if !forbid {
				problems = append(problems, location+"."+key)
			} else {
				out[key] = data[key]
			}
		}
		return out, problems
	case "array":
		list, ok := value.([]any)
		if !ok {
			return nil, []string{location}
		}
		if n, ok := wireInt(schema["minItems"]); ok && int64(len(list)) < n {
			return nil, []string{location}
		}
		if n, ok := wireInt(schema["maxItems"]); ok && int64(len(list)) > n {
			return nil, []string{location}
		}
		item, _ := schema["items"].(map[string]any)
		out := make([]any, len(list))
		problems := []string{}
		for i, raw := range list {
			parsed, errs := c.validate(item, raw, location+"."+strconv.Itoa(i))
			out[i] = parsed
			problems = append(problems, errs...)
		}
		return out, problems
	case "string":
		s, ok := value.(string)
		if !ok {
			return nil, []string{location}
		}
		if n, ok := wireInt(schema["minLength"]); ok && int64(utf8.RuneCountInString(s)) < n {
			return nil, []string{location}
		}
		if n, ok := wireInt(schema["maxLength"]); ok && int64(utf8.RuneCountInString(s)) > n {
			return nil, []string{location}
		}
		if pattern, ok := schema["pattern"].(string); ok {
			if !regexp.MustCompile(pattern).MatchString(s) {
				return nil, []string{location}
			}
		}
	case "integer":
		n, ok := domain.Integer(value)
		if !ok {
			return nil, []string{location}
		}
		if !numericBounds(schema, new(big.Rat).SetInt(n), true) {
			return nil, []string{location}
		}
	case "number":
		n, ok := domain.Float(value)
		if !ok || math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, []string{location}
		}
		rat := new(big.Rat).SetFloat64(n)
		if !numericBounds(schema, rat, false) {
			return nil, []string{location}
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return nil, []string{location}
		}
	default:
		return nil, []string{location}
	}
	if enumeration, ok := schema["enum"].([]any); ok {
		matched := false
		for _, candidate := range enumeration {
			if candidate == value {
				matched = true
				break
			}
		}
		if !matched {
			return nil, []string{location}
		}
	}
	return value, nil
}
func numericBounds(schema object, value *big.Rat, integer bool) bool {
	for _, key := range []string{"minimum", "maximum", "exclusiveMinimum"} {
		raw, exists := schema[key]
		if !exists {
			continue
		}
		bound, ok := new(big.Rat).SetString(fmt.Sprint(raw))
		if !ok {
			return false
		}
		// FastAPI's OpenAPI serializes this exact int64 bound through float64,
		// rounding 2^63-1 upward. The actual Pydantic field remains exactly int64.
		if integer && key == "maximum" && bound.Cmp(roundedInt64Maximum()) == 0 {
			bound = new(big.Rat).SetInt64(math.MaxInt64)
		}
		cmp := value.Cmp(bound)
		if key == "minimum" && cmp < 0 || key == "maximum" && cmp > 0 || key == "exclusiveMinimum" && cmp <= 0 {
			return false
		}
	}
	return true
}
func wireInt(raw any) (int64, bool) {
	if n, ok := domain.Int64(raw); ok {
		return n, true
	}
	if n, ok := raw.(json.Number); ok {
		f, err := strconv.ParseFloat(string(n), 64)
		if err == nil && f == math.Trunc(f) && f >= math.MinInt64 && f < math.MaxInt64 {
			return int64(f), true
		}
	}
	return 0, false
}
func anySlice(v any) []any { out, _ := v.([]any); return out }
func cloneWire(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := object{}
		for k, v := range x {
			out[k] = cloneWire(v)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = cloneWire(v)
		}
		return out
	}
	return v
}

func roundedInt64Maximum() *big.Rat { r, _ := new(big.Rat).SetString("9223372036854776000"); return r }
