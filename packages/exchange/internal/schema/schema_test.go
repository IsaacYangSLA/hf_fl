package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
)

func object(value any) domain.Object { m, _ := value.(map[string]any); return m }
func oracle(t *testing.T, path string) []any {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := domain.DecodeJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	return object(raw)["cases"].([]any)
}
func assertOracle(t *testing.T, c domain.Object, value any, err error) {
	t.Helper()
	if expected, hasError := c["error"]; hasError {
		var e *domain.Error
		if !errors.As(err, &e) {
			t.Fatalf("expected domain error%v, got%T %v", expected, err, err)
		}
		ex := object(expected)
		status, _ := domain.Int64(ex["status"])
		if int64(e.Status) != status || e.Code != ex["code"] || e.Detail != ex["detail"] {
			t.Fatalf("error mismatch got%+v expected%v", e, expected)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	actual, e := domain.CanonicalJSON(value)
	if e != nil {
		t.Fatal(e)
	}
	expected, e := domain.CanonicalJSON(c["result"])
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("actual%s expected%s", actual, expected)
	}
}
func TestPythonSchemaContractOracles(t *testing.T) {
	for _, raw := range oracle(t, "testdata/schema_oracle.json") {
		c := object(raw)
		t.Run(c["name"].(string), func(t *testing.T) {
			args := c["args"].([]any)
			var result any
			var err error
			switch c["operation"] {
			case "schema":
				err = ValidateSchema(args[0])
			case "metadata":
				result, err = ValidateMetadata(args[0], object(args[1]))
			case "size":
				result, err = MetadataSize(args[0])
			case "digest":
				result, err = SchemaDigest(args[0])
			case "path":
				result, err = ValidatePath(args[0])
			case "kind":
				result, err = ValidateKind(args[0])
			case "casefold":
				result = CaseFoldPath(args[0].(string))
			default:
				t.Fatal("unknown oracle operation")
			}
			assertOracle(t, c, result, err)
		})
	}
}
func TestExternalSchemaReferencesNeverLoad(t *testing.T) {
	var requests atomic.Int64
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); fmt.Fprint(w, `{"type":"object"}`) }))
	defer remote.Close()
	for _, definition := range []domain.Object{
		{"type": "object", "properties": domain.Object{"x": domain.Object{"$ref": remote.URL + "/schema"}}},
		{"type": "object", "$schema": remote.URL + "/meta"},
		{"type": "object", "$id": remote.URL + "/id"},
	} {
		if err := ValidateSchema(definition); err == nil {
			t.Fatal("external reference accepted")
		}
	}
	if requests.Load() != 0 {
		t.Fatal("external schema was loaded")
	}
}
func TestUnsupportedRegexBlocksRetainedSchema(t *testing.T) {
	definition := domain.Object{"type": "object", "properties": domain.Object{"x": domain.Object{"pattern": `\N{LATIN CAPITAL LETTER A}`}}}
	err := CheckCompatibility(definition)
	var e *domain.Error
	if !errors.As(err, &e) || e.Status != 422 || e.Code != "invalid_schema" || e.Detail != "unsupported_regex:unicode_name_escape" {
		t.Fatalf("unexpected compatibility failure%v", err)
	}
}
func TestRegexTimeoutCannotBeInvertedByLogicalKeywords(t *testing.T) {
	input := domain.Object{"v": strings.Repeat("a", 60000) + "!"}
	for _, definition := range []domain.Object{
		{"type": "object", "properties": domain.Object{"v": domain.Object{"not": domain.Object{"pattern": "^(a+)+$"}}}},
		{"type": "object", "properties": domain.Object{"v": domain.Object{"if": domain.Object{"pattern": "^(a+)+$"}, "then": false, "else": true}}},
		{"type": "object", "properties": domain.Object{"v": domain.Object{"oneOf": []any{domain.Object{"pattern": "^(a+)+$"}, domain.Object{"type": "string"}}}}},
	} {
		if err := ValidateSchema(definition); err != nil {
			t.Fatal(err)
		}
		_, err := ValidateMetadata(input, definition)
		var e *domain.Error
		if !errors.As(err, &e) || e.Code != "metadata_schema_mismatch" || e.Detail != "regex_timeout" {
			t.Fatalf("timeout inverted or hidden:%v", err)
		}
	}
}
func TestInternalNumericVocabularyCannotReinterpretClientAnnotations(t *testing.T) {
	definition := domain.Object{"type": "object", "_hf2l_python_multipleOf": false, "_hf2l_python_multipleOf_": domain.Object{"multipleOf": 0.1}, "properties": domain.Object{"v": domain.Object{"multipleOf": 2}}}
	if err := ValidateSchema(definition); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateMetadata(domain.Object{"v": 4}, definition); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateMetadata(domain.Object{"v": 3}, definition); err == nil {
		t.Fatal("multipleOf not applied")
	}
}
func TestLocalReferenceToAnnotationSchemaRetainsNumericSemantics(t *testing.T) {
	definition := domain.Object{"type": "object", "x-annotation": domain.Object{"multipleOf": 0.1}, "properties": domain.Object{"v": domain.Object{"$ref": "#/x-annotation"}}}
	if err := ValidateSchema(definition); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateMetadata(domain.Object{"v": 0.3}, definition); err == nil {
		t.Fatal("reference-target multipleOf used different arithmetic")
	}
}

func TestTypedNativeCollectionsRetainJSONDepthRules(t *testing.T) {
	var value any = map[string]string{"leaf": "value"}
	for i := 0; i < 16; i++ {
		value = domain.Object{"next": value}
	}
	if _, err := MetadataSize(value); err == nil {
		t.Fatal("typed nested map bypassed depth cap")
	}
	if _, err := MetadataSize(domain.Object(nil)); err == nil {
		t.Fatal("nil native object was accepted as JSON object")
	}
	typed := domain.Object{"items": []domain.Object{{"value": []string{"a", "b"}}}}
	if _, err := MetadataSize(typed); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateMetadata(typed, domain.Object{"type": "object", "properties": domain.Object{"items": domain.Object{"type": "array"}}}); err != nil {
		t.Fatal(err)
	}
}
func TestRegexInsideAnnotationIsNotAnEffectiveSchema(t *testing.T) {
	definition := domain.Object{"type": "object", "default": domain.Object{"pattern": string(rune(92)) + "N{SNOWMAN}", "multipleOf": 0.1}}
	if err := ValidateSchema(definition); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateMetadata(domain.Object{}, definition); err != nil {
		t.Fatal(err)
	}
}

func TestArbitraryIntegersAndMixedArithmeticOverflowFailClosed(t *testing.T) {
	huge := json.Number("1" + strings.Repeat("0", 400))
	plain := domain.Object{"type": "object", "properties": domain.Object{"v": domain.Object{"type": "integer"}}}
	if _, err := ValidateMetadata(domain.Object{"v": huge}, plain); err != nil {
		t.Fatal("arbitrary precision integer rejected:", err)
	}
	mixed := domain.Object{"type": "object", "properties": domain.Object{"v": domain.Object{"multipleOf": 2.0}}}
	if _, err := ValidateMetadata(domain.Object{"v": huge}, mixed); err == nil {
		t.Fatal("unrepresentable mixed arithmetic accepted")
	}
}
