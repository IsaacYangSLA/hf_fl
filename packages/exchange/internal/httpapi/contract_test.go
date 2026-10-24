package httpapi

import (
	"encoding/json"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func testBody(t *testing.T, action, raw string) (object, []string) {
	t.Helper()
	c, e := publicContract()
	if e != nil {
		t.Fatal(e)
	}
	for _, spec := range routeSpecs {
		if spec.action == action {
			value, syntax := decodeBody([]byte(raw), "application/json")
			if syntax != "" {
				return nil, []string{syntax}
			}
			return c.validateBody(spec, value)
		}
	}
	t.Fatalf("missing route %s", action)
	return nil, nil
}
func TestOpenAPIIsExactPublicContractAndActualRouteInventory(t *testing.T) {
	data, e := OpenAPI()
	if e != nil {
		t.Fatal(e)
	}
	reference, e := os.ReadFile(filepath.Join("..", "..", "..", "..", "docs", "generated", "exchange-api.json"))
	if e != nil {
		t.Fatal(e)
	}
	if string(data) != string(reference) {
		t.Fatal("public contract differs from checked-in reference")
	}
	if len(RouteInventory()) != 37 {
		t.Fatal("wrong public operation count")
	}
	c, e := compileContract(data)
	if e != nil {
		t.Fatal(e)
	}
	if len(c.operations) != 37 {
		t.Fatal("wrong compiled operation count")
	}
	data[0] = 'x'
	again, e := OpenAPI()
	if e != nil || again[0] != '{' {
		t.Fatal("caller can mutate embedded contract")
	}
}
func TestUnsupportedRequestKeywordCannotBeSilentlyIgnored(t *testing.T) {
	data, e := OpenAPI()
	if e != nil {
		t.Fatal(e)
	}
	var doc object
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	if e = dec.Decode(&doc); e != nil {
		t.Fatal(e)
	}
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	schemas["SpaceBody"].(map[string]any)["maxProperties"] = json.Number("10")
	changed, e := json.Marshal(doc)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = compileContract(changed); e == nil {
		t.Fatal("unsupported request constraint ignored")
	}
}
func TestStrictModelFieldsDefaultsNullsAndUnicode(t *testing.T) {
	body, errs := testBody(t, "create_space", `{"name":"Example"}`)
	if len(errs) != 0 || body["profile"] != "generic.v1" || body["quota_bytes"] != json.Number("10737418240") {
		t.Fatalf("defaults %+v %+v", body, errs)
	}
	cases := []struct{ action, raw, location string }{
		{"create_space", `{"name":true}`, "body.name"},
		{"create_space", `{"name":"x","quota_bytes":1.0}`, "body.quota_bytes"},
		{"create_space", `{"name":"x","quota_bytes":true}`, "body.quota_bytes"},
		{"create_space", `{"name":"x","quota_bytes":"1"}`, "body.quota_bytes"},
		{"create_space", `{"name":"x","password":"do-not-echo"}`, "body.password"},
		{"verify_workload_grant", `{"extra":1}`, "body.extra"},
		{"grants", `{"numbers":[true]}`, "body.numbers.0"},
		{"put_member", `{"roles":["root"]}`, "body.roles.0"},
	}
	for _, tc := range cases {
		t.Run(tc.action+"/"+tc.location+tc.raw, func(t *testing.T) {
			_, errs := testBody(t, tc.action, tc.raw)
			if !reflect.DeepEqual(errs, []string{tc.location}) {
				t.Fatalf("locations %v", errs)
			}
			if strings.Contains(strings.Join(errs, ";"), "do-not-echo") {
				t.Fatal("value leaked in validation error")
			}
		})
	}
	for _, count := range []int{128, 129} {
		raw := `{"name":"` + strings.Repeat("😀", count) + `"}`
		_, errs := testBody(t, "create_space", raw)
		if (len(errs) == 0) != (count == 128) {
			t.Fatalf("Unicode codepoint bound count%d: %v", count, errs)
		}
	}
	b, errs := testBody(t, "put_member", `{"roles":[],"subject":null,"bindings":{"nullable":null}}`)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if _, present := b["subject"]; present {
		t.Fatal("None model field retained")
	}
	if value, present := b["bindings"].(map[string]any)["nullable"]; !present || value != nil {
		t.Fatal("None dictionary entry removed")
	}
}
func TestExactInt64WireMaximumDespiteRoundedOpenAPI(t *testing.T) {
	for _, value := range []string{"9223372036854775807", "9223372036854775808", "9223372036854775999", "9223372036854776000"} {
		_, errs := testBody(t, "create_space", `{"name":"x","quota_bytes":`+value+`}`)
		if (len(errs) == 0) != (value == "9223372036854775807") {
			t.Fatalf("int64 bound %s: %v", value, errs)
		}
	}
	body, errs := testBody(t, "renew", `{"fence":9223372036854775808}`)
	if len(errs) != 0 {
		t.Fatal("unbounded positive fence rejected")
	}
	if fenceValue(body["fence"]) != 0 {
		t.Fatal("overflow fence wrapped into valid authority")
	}
}
func TestFactoryDefaultsAreFreshAndAliasesMatchWire(t *testing.T) {
	first, errs := testBody(t, "put_policy", `{}`)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	first["publish_roles"].([]any)[0] = "changed"
	second, errs := testBody(t, "put_policy", `{}`)
	if len(errs) > 0 || second["publish_roles"].([]any)[0] != "contributor" {
		t.Fatal("shared mutable factory default")
	}
	body, errs := testBody(t, "register_type", `{"schema":{"type":"object"},"visibility":null}`)
	if len(errs) > 0 || body["schema"] == nil {
		t.Fatalf("schema alias lost %+v %v", body, errs)
	}
	if _, ok := body["visibility"]; ok {
		t.Fatal("nullable policy default not omitted")
	}
}
func TestWireDecodeExactDocumentAndUnicodeSafety(t *testing.T) {
	for _, raw := range []string{`{"name":}`, `{"name":"x"} {}`, `{"name":"\ud800"}`, string([]byte{'{', '"', 'n', 'a', 'm', 'e', '"', ':', '"', 0xff, '"', '}'})} {
		_, location := decodeBody([]byte(raw), "application/json")
		if location == "" {
			t.Fatalf("invalid document accepted %q", raw)
		}
	}
	value, location := decodeBody([]byte(`{"name":"first","name":"last"}`), "application/json")
	if location != "" || value.(map[string]any)["name"] != "last" {
		t.Fatal("ordinary JSON duplicate semantics changed")
	}
	if _, location = decodeBody([]byte(`{"name":"\ud83d\ude00"}`), "application/json"); location != "" {
		t.Fatal("valid surrogate pair rejected")
	}
	value, location = decodeBody([]byte(`{"name":"x"}`), "text/plain")
	if location != "" {
		t.Fatal("content type should fail model validation after authentication")
	}
	if _, ok := value.([]byte); !ok {
		t.Fatal("text body incorrectly parsed as JSON")
	}
}
func TestQueryCoercionMatchesFrozenPydanticOracle(t *testing.T) {
	cases := map[string]string{"1": "1", "1.0": "1", "01": "1", "+1": "1", " 1 ": "1", "1e0": "", "1_0": "10", "١": "", "9223372036854775808": "9223372036854775808", "-0": "0", "0.0": "0", "1.00": "1", "1.2": ""}
	for raw, want := range cases {
		got, ok := queryInteger(raw)
		if want == "" {
			if ok {
				t.Fatalf("accepted %q", raw)
			}
			continue
		}
		expected, _ := new(big.Int).SetString(want, 10)
		if !ok || got.Cmp(expected) != 0 {
			t.Fatalf("query %q: %v/%v", raw, got, ok)
		}
	}
}
func TestConcurrencyHeaderContracts(t *testing.T) {
	cases := []struct {
		match, none       string
		hasMatch, hasNone bool
		want              string
		code              string
	}{
		{"", "", false, false, "", "precondition_required"},
		{"", "*", false, true, "*", ""},
		{`"1"`, "", true, false, "1", ""},
		{"1", "*", true, true, "", "ambiguous_precondition"},
		{`W/"1"`, "", true, false, "", "invalid_precondition"},
		{"1,2", "", true, false, "", "invalid_precondition"},
		{"", "1", false, true, "", "invalid_precondition"},
	}
	for _, tc := range cases {
		h := http.Header{}
		if tc.hasMatch {
			h.Set("If-Match", tc.match)
		}
		if tc.hasNone {
			h.Set("If-None-Match", tc.none)
		}
		got, err := precondition(h, true)
		if tc.code == "" {
			if err != nil || got != tc.want {
				t.Fatalf("headers %+v: %s %v", tc, got, err)
			}
		} else if err == nil || err.Error() != tc.code {
			t.Fatalf("expected %s got%v", tc.code, err)
		}
	}
	h := http.Header{"If-None-Match": []string{"*"}}
	if _, err := precondition(h, false); err == nil || err.Error() != "precondition_required" {
		t.Fatal("patch unexpectedly uses If-None-Match")
	}
}
