// Package schema implements bounded, offline JSON Schema and attachment rules.
package schema

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/cases"
)

const (
	MaxMetadataBytes = 65536
	MaxSchemaBytes   = 65536
	MaxAttachments   = 256
	Dialect          = "https://json-schema.org/draft/2020-12/schema"
	resourceURL      = "https://hf2l.invalid/exchange/schema.json"
)

var kindPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

type offlineLoader struct{}

func (offlineLoader) Load(string) (any, error) {
	return nil, errors.New("external schema loading disabled")
}
func compiler() *jsonschema.Compiler {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(offlineLoader{})
	c.UseRegexpEngine(compileRegexp)
	return c
}
func MetadataSize(value any) (int64, error) {
	m, ok := value.(map[string]any)
	if !ok || m == nil {
		return 0, domain.Err(422, "metadata_must_be_object")
	}
	if err := bounded(m, 0); err != nil {
		return 0, err
	}
	encoded, err := domain.CanonicalJSON(m)
	if err != nil {
		return 0, domain.Err(422, "invalid_json")
	}
	if len(encoded) > MaxMetadataBytes {
		return 0, domain.Err(422, "metadata_too_large")
	}
	return int64(len(encoded)), nil
}
func bounded(value any, depth int) error {
	if depth > 16 {
		return domain.Err(422, "metadata_too_deep")
	}
	switch v := value.(type) {
	case map[string]any:
		for _, child := range v {
			if err := bounded(child, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range v {
			if err := bounded(child, depth+1); err != nil {
				return err
			}
		}
	default:
		rv := reflect.ValueOf(value)
		if !rv.IsValid() {
			return nil
		}
		switch rv.Kind() {
		case reflect.Map:
			if rv.Type().Key().Kind() != reflect.String {
				return domain.Err(422, "invalid_json")
			}
			iter := rv.MapRange()
			for iter.Next() {
				if err := bounded(iter.Value().Interface(), depth+1); err != nil {
					return err
				}
			}
		case reflect.Slice, reflect.Array:
			for i := 0; i < rv.Len(); i++ {
				if err := bounded(rv.Index(i).Interface(), depth+1); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func SchemaDigest(value any) (string, error) {
	encoded, err := domain.CanonicalJSON(value)
	if err != nil {
		return "", domain.Err(422, "invalid_json")
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
func ValidatePath(value any) (string, error) {
	path, ok := value.(string)
	if !ok || path == "" || !utf8.ValidString(path) || len(path) > 256 || strings.ContainsAny(path, `\:`) || strings.HasPrefix(path, "/") {
		return "", domain.Err(422, "invalid_attachment_path")
	}
	for _, r := range path {
		if r < 32 || r == 127 {
			return "", domain.Err(422, "invalid_attachment_path")
		}
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return "", domain.Err(422, "invalid_attachment_path")
		}
	}
	return path, nil
}
func CaseFoldPath(path string) string { return cases.Fold().String(path) }
func ValidateKind(value any) (string, error) {
	s, ok := value.(string)
	if !ok || !kindPattern.MatchString(s) {
		return "", domain.Err(422, "invalid_kind")
	}
	return s, nil
}
func normalized(value any) (any, error) {
	b, err := domain.CanonicalJSON(value)
	if err != nil {
		return nil, err
	}
	return domain.DecodeJSON(b)
}
func resolve(root any, ref string) (any, error) {
	target := root
	for _, raw := range strings.Split(ref[2:], "/") {
		token := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		switch current := target.(type) {
		case map[string]any:
			var present bool
			target, present = current[token]
			if !present {
				return nil, domain.Err(422, "schema_reference_missing")
			}
		case []any:
			index, err := strconv.Atoi(token)
			if err != nil {
				return nil, domain.Err(422, "schema_reference_missing")
			}
			if index < 0 {
				index += len(current)
			}
			if index < 0 || index >= len(current) {
				return nil, domain.Err(422, "schema_reference_missing")
			}
			target = current[index]
		default:
			return nil, domain.Err(422, "schema_reference_missing")
		}
	}
	return target, nil
}
func inspect(root, value any, depth int) error {
	if depth > 16 {
		return domain.Err(422, "schema_too_deep")
	}
	switch v := value.(type) {
	case map[string]any:
		for _, k := range []string{"$id", "$dynamicRef", "$recursiveRef"} {
			if _, present := v[k]; present {
				return domain.Err(422, "schema_reference_unsupported")
			}
		}
		if ref, present := v["$ref"]; present {
			text, ok := ref.(string)
			if !ok || !strings.HasPrefix(text, "#/") {
				return domain.Err(422, "schema_reference_unsupported")
			}
			target, err := resolve(root, text)
			if err != nil {
				return err
			}
			if err = inspect(root, target, depth+1); err != nil {
				return err
			}
		}
		for _, child := range v {
			if err := inspect(root, child, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range v {
			if err := inspect(root, child, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
func schemaRegexError(err error) error {
	var unsupported *UnsupportedRegexError
	if errors.As(err, &unsupported) {
		return domain.Err(422, "invalid_schema", "unsupported_regex:"+unsupported.Feature)
	}
	return domain.Err(422, "invalid_schema")
}
func ValidateSchema(value any) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			switch recovered.(type) {
			case RegexTimeoutError, *RegexTimeoutError:
				err = domain.Err(422, "invalid_schema", "regex_timeout")
			default:
				panic(recovered)
			}
		}
	}()

	original, ok := value.(map[string]any)
	if !ok || original == nil {
		return domain.Err(422, "invalid_schema")
	}
	encoded, err := domain.CanonicalJSON(original)
	if err != nil {
		return domain.Err(422, "invalid_json")
	}
	if len(encoded) > MaxSchemaBytes {
		return domain.Err(422, "invalid_schema")
	}
	if dialect, present := original["$schema"]; present && dialect != Dialect {
		return domain.Err(422, "unsupported_schema_dialect_or_root")
	}
	if original["type"] != "object" {
		return domain.Err(422, "unsupported_schema_dialect_or_root")
	}
	normalizedSchema, err := normalized(original)
	if err != nil {
		return domain.Err(422, "invalid_json")
	}
	if err = inspect(normalizedSchema, normalizedSchema, 0); err != nil {
		return err
	}
	if err = walkSchemas(normalizedSchema, func(node map[string]any) error {
		if pattern, present := node["pattern"]; present {
			if text, ok := pattern.(string); ok {
				if _, err := compileRegexp(text); err != nil {
					return schemaRegexError(err)
				}
			}
		}
		if patterns, ok := node["patternProperties"].(map[string]any); ok {
			for pattern := range patterns {
				if _, err := compileRegexp(pattern); err != nil {
					return schemaRegexError(err)
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	c := compiler()
	if err = c.AddResource(resourceURL, normalizedSchema); err != nil {
		return domain.Err(422, "invalid_schema")
	}
	if _, err = c.Compile(resourceURL); err != nil {
		return domain.Err(422, "invalid_schema")
	}
	return nil
}

// CheckCompatibility validates a retained immutable revision before native admission.
func CheckCompatibility(value domain.Object) error { return ValidateSchema(value) }
func ValidateMetadata(value any, definition domain.Object) (size int64, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			switch recovered.(type) {
			case RegexTimeoutError, *RegexTimeoutError:
				size = 0
				err = domain.Err(422, "metadata_schema_mismatch", "regex_timeout")
			default:
				panic(recovered)
			}
		}
	}()
	size, err = MetadataSize(value)
	if err != nil {
		return 0, err
	}
	metadata, err := normalized(value)
	if err != nil {
		return 0, domain.Err(422, "invalid_json")
	}
	raw, err := normalized(definition)
	if err != nil {
		return 0, domain.Err(422, "metadata_schema_mismatch")
	}
	c, prepared, err := compatibilityCompiler(raw)
	if err != nil {
		return 0, domain.Err(422, "metadata_schema_mismatch")
	}
	if err = c.AddResource(resourceURL, prepared); err != nil {
		return 0, domain.Err(422, "metadata_schema_mismatch")
	}
	sch, err := c.Compile(resourceURL)
	if err != nil {
		return 0, domain.Err(422, "metadata_schema_mismatch")
	}
	if err = sch.Validate(metadata); err != nil {
		return 0, domain.Err(422, "metadata_schema_mismatch")
	}
	return size, nil
}

// walkSchemas visits only effective schema nodes, including targets of local
// references. Annotation/enum/default objects remain ordinary JSON data.
func walkSchemas(root any, visit func(map[string]any) error) error {
	visited := map[string]bool{}
	var walk func(any, string) error
	walk = func(value any, path string) error {
		if visited[path] {
			return nil
		}
		visited[path] = true
		node, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		if err := visit(node); err != nil {
			return err
		}
		if ref, ok := node["$ref"].(string); ok && strings.HasPrefix(ref, "#/") {
			target, err := resolve(root, ref)
			if err != nil {
				return err
			}
			if err = walk(target, ref[1:]); err != nil {
				return err
			}
		}
		for _, key := range []string{"additionalProperties", "additionalItems", "contains", "contentSchema", "else", "if", "items", "not", "propertyNames", "then", "unevaluatedItems", "unevaluatedProperties"} {
			if child, present := node[key]; present {
				if err := walk(child, path+"/"+key); err != nil {
					return err
				}
			}
		}
		for _, key := range []string{"allOf", "anyOf", "oneOf", "prefixItems"} {
			if children, ok := node[key].([]any); ok {
				for i, child := range children {
					if err := walk(child, fmt.Sprintf("%s/%s/%d", path, key, i)); err != nil {
						return err
					}
				}
			}
		}
		for _, key := range []string{"$defs", "definitions", "dependentSchemas", "patternProperties", "properties"} {
			if children, ok := node[key].(map[string]any); ok {
				for name, child := range children {
					token := strings.ReplaceAll(strings.ReplaceAll(name, "~", "~0"), "/", "~1")
					if err := walk(child, path+"/"+key+"/"+token); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	return walk(root, "")
}
